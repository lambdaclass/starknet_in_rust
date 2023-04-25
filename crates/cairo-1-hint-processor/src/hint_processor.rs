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
use std::collections::HashMap;

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

    fn assert_le_find_small_arcs(
        &self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        range_check_ptr: &ResOperand,
        a: &ResOperand,
        b: &ResOperand,
    ) -> Result<(), HintError> {
        let a_val = res_operand_get_val(vm, a)?;
        let b_val = res_operand_get_val(vm, b)?;
        let mut lengths_and_indices = vec![
            (a_val.clone(), 0),
            (b_val.clone() - a_val, 1),
            (Felt252::from(-1) - b_val, 2),
        ];
        lengths_and_indices.sort();
        exec_scopes.assign_or_update_variable("excluded_arc", Box::new(lengths_and_indices[2].1));
        // ceil((PRIME / 3) / 2 ** 128).
        let prime_over_3_high = 3544607988759775765608368578435044694_u128;
        // ceil((PRIME / 2) / 2 ** 128).
        let prime_over_2_high = 5316911983139663648412552867652567041_u128;
        let (range_check_base, range_check_offset) = extract_buffer(range_check_ptr);
        let range_check_ptr = get_ptr(vm, range_check_base, &range_check_offset)?;
        vm.insert_value(
            range_check_ptr,
            Felt252::from(lengths_and_indices[0].0.to_biguint() % prime_over_3_high),
        )?;
        vm.insert_value(
            (range_check_ptr + 1)?,
            Felt252::from(lengths_and_indices[0].0.to_biguint() / prime_over_3_high),
        )?;
        vm.insert_value(
            (range_check_ptr + 2)?,
            Felt252::from(lengths_and_indices[1].0.to_biguint() % prime_over_2_high),
        )?;
        vm.insert_value(
            (range_check_ptr + 3)?,
            Felt252::from(lengths_and_indices[1].0.to_biguint() / prime_over_2_high),
        )?;
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
        exec_scopes: &mut ExecutionScopes,
        //Data structure that can be downcasted to the structure generated by compile_hint
        hint_data: &Box<dyn std::any::Any>,
        //Constant values extracted from the program specification.
        _constants: &HashMap<String, Felt252>,
    ) -> Result<(), HintError> {
        let hint = hint_data.downcast_ref::<Hint>().unwrap();
        match hint {
            Hint::AllocSegment { dst } => self.alloc_segment(vm, dst),
            Hint::TestLessThan { lhs, rhs, dst } => self.test_less_than(vm, lhs, rhs, dst),
            Hint::AssertLeFindSmallArcs {
                range_check_ptr,
                a,
                b,
            } => self.assert_le_find_small_arcs(vm, exec_scopes, range_check_ptr, a, b),
            Hint::TestLessThanOrEqual { lhs, rhs, dst } => {
                self.test_less_than_or_equal(vm, lhs, rhs, dst)
            }
            _ => todo!(),
        }
    }
}
