use std::collections::HashMap;

use cairo_lang_casm::{
    hints::Hint,
    operand::{CellRef, DerefOrImmediate, Operation, Register, ResOperand},
};
use cairo_rs::{
    hint_processor::hint_processor_definition::HintProcessor,
    types::exec_scope::ExecutionScopes,
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        errors::{hint_errors::HintError, vm_errors::VirtualMachineError},
        vm_core::VirtualMachine,
    },
};
use felt::Felt252;
use num_integer::Integer;
/// HintProcessor for Cairo 1 compiler hints.
struct Cairo1HintProcessor {}

fn cell_ref_to_relocatable(cell_ref: &CellRef, vm: &VirtualMachine) -> Relocatable {
    let base = match cell_ref.register {
        Register::AP => vm.get_ap(),
        Register::FP => vm.get_fp(),
    };
    (base + (cell_ref.offset as i32)).unwrap()
}

fn get_cell_val(vm: &VirtualMachine, cell: &CellRef) -> Result<Felt252, VirtualMachineError> {
    Ok(vm
        .get_integer(cell_ref_to_relocatable(cell, vm))?
        .as_ref()
        .clone())
}

fn get_ptr(
    vm: &VirtualMachine,
    cell: &CellRef,
    offset: &Felt252,
) -> Result<Relocatable, VirtualMachineError> {
    Ok((vm.get_relocatable(cell_ref_to_relocatable(cell, vm))? + offset)?)
}

fn get_double_deref_val(
    vm: &VirtualMachine,
    cell: &CellRef,
    offset: &Felt252,
) -> Result<Felt252, VirtualMachineError> {
    Ok(vm.get_integer(get_ptr(vm, cell, offset)?)?.as_ref().clone())
}

fn res_operand_get_val(
    vm: &VirtualMachine,
    res_operand: &ResOperand,
) -> Result<Felt252, VirtualMachineError> {
    match res_operand {
        ResOperand::Deref(cell) => get_cell_val(vm, cell),
        ResOperand::DoubleDeref(cell, offset) => get_double_deref_val(vm, cell, &(*offset).into()),
        ResOperand::Immediate(x) => Ok(Felt252::from(x.value.clone())),
        ResOperand::BinOp(op) => {
            let a = get_cell_val(vm, &op.a)?;
            let b = match &op.b {
                DerefOrImmediate::Deref(cell) => get_cell_val(vm, cell)?,
                DerefOrImmediate::Immediate(x) => Felt252::from(x.value.clone()),
            };
            match op.op {
                Operation::Add => Ok(a + b),
                Operation::Mul => Ok(a * b),
            }
        }
    }
}

impl Cairo1HintProcessor {
    fn alloc_segment(&mut self, vm: &mut VirtualMachine, dst: &CellRef) -> Result<(), HintError> {
        let segment = vm.add_memory_segment();
        vm.insert_value(cell_ref_to_relocatable(dst, vm), segment)
            .map_err(HintError::from)
    }

    fn test_less_than(
        &self,
        vm: &mut VirtualMachine,
        lhs: &ResOperand,
        rhs: &ResOperand,
        dst: &CellRef,
    ) -> Result<(), HintError> {
        let lhs_value = res_operand_get_val(vm, lhs)?;
        let rhs_value = res_operand_get_val(vm, rhs)?;
        let result = if lhs_value < rhs_value {
            Felt252::from(1)
        } else {
            Felt252::from(0)
        };

        vm.insert_value(
            cell_ref_to_relocatable(dst, vm),
            MaybeRelocatable::from(result),
        )
        .map_err(HintError::from)
    }

    fn test_less_than_or_equal(
        &self,
        vm: &mut VirtualMachine,
        lhs: &ResOperand,
        rhs: &ResOperand,
        dst: &CellRef,
    ) -> Result<(), HintError> {
        let lhs_value = res_operand_get_val(vm, lhs)?;
        let rhs_value = res_operand_get_val(vm, rhs)?;
        let result = if lhs_value <= rhs_value {
            Felt252::from(1)
        } else {
            Felt252::from(0)
        };

        vm.insert_value(
            cell_ref_to_relocatable(dst, vm),
            MaybeRelocatable::from(result),
        )
        .map_err(HintError::from)
    }

    #[allow(unused)]
    fn uint256_square_root(
        &self,
        vm: &mut VirtualMachine,
        value_low: &ResOperand,
        value_high: &ResOperand,
        sqrt0: &CellRef,
        sqrt1: &CellRef,
        remainder_low: &CellRef,
        remainder_high: &CellRef,
        sqrt_mul_2_minus_remainder_ge_u128: &CellRef,
    ) -> Result<(), HintError> {
        let pow_2_128 = Felt252::from(u128::MAX) + 1u32;
        let pow_2_64 = Felt252::from(u64::MAX) + 1u32;
        let value_low = res_operand_get_val(vm, value_low)?;
        let value_high = res_operand_get_val(vm, value_high)?;
        let value = value_low + value_high * pow_2_128.clone();
        let sqrt = value.sqrt();
        let remainder = value - sqrt.clone() * sqrt.clone();
        let sqrt_mul_2_minus_remainder_ge_u128_val =
            sqrt.clone() * Felt252::from(2u32) - remainder.clone() >= pow_2_128;

        let (sqrt1_val, sqrt0_val) = sqrt.div_rem(&pow_2_64);
        vm.insert_value(cell_ref_to_relocatable(sqrt0, vm), Felt252::from(sqrt0_val))?;
        vm.insert_value(cell_ref_to_relocatable(sqrt1, vm), Felt252::from(sqrt1_val))?;

        let (remainder_high_val, remainder_low_val) = remainder.div_rem(&pow_2_128);

        vm.insert_value(
            cell_ref_to_relocatable(remainder_low, vm),
            Felt252::from(remainder_low_val),
        )?;
        vm.insert_value(
            cell_ref_to_relocatable(remainder_high, vm),
            Felt252::from(remainder_high_val),
        )?;
        vm.insert_value(
            cell_ref_to_relocatable(sqrt_mul_2_minus_remainder_ge_u128, vm),
            Felt252::from(usize::from(sqrt_mul_2_minus_remainder_ge_u128_val)),
        )?;

        Ok(())
    }
}

impl HintProcessor for Cairo1HintProcessor {
    fn execute_hint(
        &mut self,
        //Proxy to VM, contains references to necessary data
        //+ MemoryProxy, which provides the necessary methods to manipulate memory
        vm: &mut VirtualMachine,
        //Proxy to ExecutionScopes, provides the necessary methods to manipulate the scopes and
        //access current scope variables
        _exec_scopes: &mut ExecutionScopes,
        //Data structure that can be downcasted to the structure generated by compile_hint
        hint_data: &Box<dyn std::any::Any>,
        //Constant values extracted from the program specification.
        _constants: &HashMap<String, Felt252>,
    ) -> Result<(), HintError> {
        let hint = hint_data.downcast_ref::<Hint>().unwrap();
        match hint {
            Hint::AllocSegment { dst } => self.alloc_segment(vm, dst),
            Hint::TestLessThan { lhs, rhs, dst } => self.test_less_than(vm, lhs, rhs, dst),
            Hint::TestLessThanOrEqual { lhs, rhs, dst } => {
                self.test_less_than_or_equal(vm, lhs, rhs, dst)
            }
            _ => todo!(),
        }
    }
}
