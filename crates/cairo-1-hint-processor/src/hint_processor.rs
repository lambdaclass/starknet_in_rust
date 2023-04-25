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

    fn linear_split(
        &self,
        vm: &mut VirtualMachine,
        value: &ResOperand,
        scalar: &ResOperand,
        max_x: &ResOperand,
        x: &CellRef,
        y: &CellRef,
    ) -> Result<(), HintError> {
        let value = res_operand_get_val(vm, value)?;
        let scalar = res_operand_get_val(vm, scalar)?;
        let max_x = res_operand_get_val(vm, max_x)?;
        let x_value = (value.clone() / scalar.clone()).min(max_x);
        let y_value = value - x_value.clone() * scalar;

        vm.insert_value(cell_ref_to_relocatable(x, vm), x_value)
            .map_err(HintError::from)?;
        vm.insert_value(cell_ref_to_relocatable(y, vm), y_value)
            .map_err(HintError::from)?;
        Ok(())
    }

    fn assert_le_is_second_excluded(
        &self,
        vm: &mut VirtualMachine,
        skip_exclude_b_minus_a: &CellRef,
        exec_scopes: &mut ExecutionScopes,
    ) -> Result<(), HintError> {
        let excluded_arc: i32 = exec_scopes.get("excluded_arc")?;
        let val = if excluded_arc != 1 {
            Felt252::from(1)
        } else {
            Felt252::from(0)
        };

        vm.insert_value(cell_ref_to_relocatable(skip_exclude_b_minus_a, vm), val)?;
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
            Hint::TestLessThanOrEqual { lhs, rhs, dst } => {
                self.test_less_than_or_equal(vm, lhs, rhs, dst)
            }
            Hint::LinearSplit {
                value,
                scalar,
                max_x,
                x,
                y,
            } => self.linear_split(vm, value, scalar, max_x, x, y),
            Hint::AssertLeIsSecondArcExcluded {
                skip_exclude_b_minus_a,
            } => self.assert_le_is_second_excluded(vm, skip_exclude_b_minus_a, exec_scopes),
            _ => todo!(),
        }
    }
}
