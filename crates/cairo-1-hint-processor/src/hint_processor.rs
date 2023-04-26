use super::dict_manager::DictManagerExecScope;
use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use ark_ff::{Field, PrimeField};
use ark_std::UniformRand;
use cairo_lang_casm::{
    hints::{CoreHint, Hint},
    operand::{BinOpOperand, CellRef, DerefOrImmediate, Operation, Register, ResOperand},
};
use cairo_lang_utils::extract_matches;
use cairo_rs::{
    hint_processor::hint_processor_definition::HintProcessor,
    types::exec_scope::ExecutionScopes,
    types::relocatable::MaybeRelocatable,
    types::relocatable::Relocatable,
    vm::errors::vm_errors::VirtualMachineError,
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};

use felt::felt_str as felt252_str;
use felt::Felt252;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::cast::ToPrimitive;
use num_traits::identities::Zero;
use std::{collections::HashMap, ops::Mul};

#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[generator = "3"]

/// Returns the Beta value of the Starkware elliptic curve.
struct FqConfig;
type Fq = Fp256<MontBackend<FqConfig, 4>>;

fn get_beta() -> Felt252 {
    felt252_str!("3141592653589793238462643383279502884197169399375105820974944592307816406665")
}
/// HintProcessor for Cairo 1 compiler hints.
struct Cairo1HintProcessor {}

/// Extracts a parameter assumed to be a buffer.
fn extract_buffer(buffer: &ResOperand) -> Result<(&CellRef, Felt252), HintError> {
    let (cell, base_offset) = match buffer {
        ResOperand::Deref(cell) => (cell, 0.into()),
        ResOperand::BinOp(BinOpOperand {
            op: Operation::Add,
            a,
            b,
        }) => (
            a,
            extract_matches!(b, DerefOrImmediate::Immediate)
                .clone()
                .value
                .into(),
        ),
        _ => {
            return Err(HintError::CustomHint(
                "Illegal argument for a buffer.".to_string(),
            ))
        }
    };
    Ok((cell, base_offset))
}

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

/// Fetches the value of `res_operand` from the vm.
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

    fn square_root(
        &self,
        vm: &mut VirtualMachine,
        value: &ResOperand,
        dst: &CellRef,
    ) -> Result<(), HintError> {
        let value = res_operand_get_val(vm, value)?;
        let result = value.sqrt();
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
        let (range_check_base, range_check_offset) = extract_buffer(range_check_ptr)?;
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
        )
        .map_err(HintError::from)
    }

    fn div_mod(
        &self,
        vm: &mut VirtualMachine,
        lhs: &ResOperand,
        rhs: &ResOperand,
        quotient: &CellRef,
        remainder: &CellRef,
    ) -> Result<(), HintError> {
        let lhs_value = res_operand_get_val(vm, lhs)?.to_biguint();
        let rhs_value = res_operand_get_val(vm, rhs)?.to_biguint();
        let quotient_value = Felt252::new(lhs_value.clone() / rhs_value.clone());
        let remainder_value = Felt252::new(lhs_value % rhs_value);
        vm.insert_value(
            cell_ref_to_relocatable(quotient, vm),
            MaybeRelocatable::from(quotient_value),
        )?;
        vm.insert_value(
            cell_ref_to_relocatable(remainder, vm),
            MaybeRelocatable::from(remainder_value),
        )
        .map_err(HintError::from)
    }

    fn get_segment_arena_index(
        &self,
        vm: &mut VirtualMachine,
        exec_scopes: &ExecutionScopes,
        dict_end_ptr: &ResOperand,
        dict_index: &CellRef,
    ) -> Result<(), HintError> {
        let (dict_base, dict_offset) = extract_buffer(dict_end_ptr)?;
        let dict_address = get_ptr(vm, dict_base, &dict_offset)?;
        let dict_manager_exec_scope = exec_scopes
            .get_ref::<DictManagerExecScope>("dict_manager_exec_scope")
            .expect("Trying to read from a dict while dict manager was not initialized.");
        let dict_infos_index = dict_manager_exec_scope.get_dict_infos_index(dict_address);
        vm.insert_value(
            cell_ref_to_relocatable(dict_index, vm),
            Felt252::from(dict_infos_index),
        )
        .map_err(HintError::from)
    }

    #[allow(clippy::too_many_arguments)]
    fn uint256_div_mod(
        &self,
        vm: &mut VirtualMachine,
        dividend_low: &ResOperand,
        dividend_high: &ResOperand,
        divisor_low: &ResOperand,
        divisor_high: &ResOperand,
        quotient0: &CellRef,
        quotient1: &CellRef,
        divisor0: &CellRef,
        divisor1: &CellRef,
        extra0: &CellRef,
        extra1: &CellRef,
        remainder_low: &CellRef,
        remainder_high: &CellRef,
    ) -> Result<(), HintError> {
        let pow_2_128 = Felt252::from(u128::MAX) + 1u32;
        let pow_2_64 = Felt252::from(u64::MAX) + 1u32;
        let dividend_low = res_operand_get_val(vm, dividend_low)?;
        let dividend_high = res_operand_get_val(vm, dividend_high)?;
        let divisor_low = res_operand_get_val(vm, divisor_low)?;
        let divisor_high = res_operand_get_val(vm, divisor_high)?;
        let dividend = dividend_low + dividend_high.mul(pow_2_128.clone());
        let divisor = divisor_low + divisor_high.clone() * pow_2_128.clone();
        let quotient = dividend.clone() / divisor.clone();
        let remainder = dividend % divisor.clone();

        // Guess quotient limbs.
        let (quotient, limb) = quotient.div_rem(&pow_2_64);
        vm.insert_value(cell_ref_to_relocatable(quotient0, vm), limb)?;
        let (quotient, limb) = quotient.div_rem(&pow_2_64);
        vm.insert_value(cell_ref_to_relocatable(quotient1, vm), limb)?;
        let (quotient, limb) = quotient.div_rem(&pow_2_64);
        if divisor_high.is_zero() {
            vm.insert_value(cell_ref_to_relocatable(extra0, vm), limb)?;
            vm.insert_value(cell_ref_to_relocatable(extra1, vm), quotient)?;
        }

        // Guess divisor limbs.
        let (divisor, limb) = divisor.div_rem(&pow_2_64);
        vm.insert_value(cell_ref_to_relocatable(divisor0, vm), limb)?;
        let (divisor, limb) = divisor.div_rem(&pow_2_64);
        vm.insert_value(cell_ref_to_relocatable(divisor1, vm), limb)?;
        let (divisor, limb) = divisor.div_rem(&pow_2_64);
        if !divisor_high.is_zero() {
            vm.insert_value(cell_ref_to_relocatable(extra0, vm), limb)?;
            vm.insert_value(cell_ref_to_relocatable(extra1, vm), divisor)?;
        }

        // Guess remainder limbs.
        vm.insert_value(
            cell_ref_to_relocatable(remainder_low, vm),
            remainder.clone() % pow_2_128.clone(),
        )?;
        vm.insert_value(
            cell_ref_to_relocatable(remainder_high, vm),
            remainder / pow_2_128,
        )?;
        Ok(())
    }

    fn assert_le_if_first_arc_exclueded(
        &self,
        vm: &mut VirtualMachine,
        skip_exclude_a_flag: &CellRef,
        exec_scopes: &mut ExecutionScopes,
    ) -> Result<(), HintError> {
        let excluded_arc: i32 = exec_scopes.get("excluded_arc")?;
        let val = if excluded_arc != 0 {
            Felt252::from(1)
        } else {
            Felt252::from(0)
        };

        vm.insert_value(cell_ref_to_relocatable(skip_exclude_a_flag, vm), val)?;
        Ok(())
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

    fn random_ec_point(
        &self,
        vm: &mut VirtualMachine,
        x: &CellRef,
        y: &CellRef,
    ) -> Result<(), HintError> {
        let beta = Fq::from(get_beta().to_biguint());

        let mut rng = ark_std::test_rng();
        let (random_x, random_y_squared) = loop {
            let random_x = Fq::rand(&mut rng);
            let random_y_squared = random_x * random_x * random_x + random_x + beta;
            if random_y_squared.legendre().is_qr() {
                break (random_x, random_y_squared);
            }
        };

        let x_bigint: BigUint = random_x.into_bigint().into();
        let y_bigint: BigUint = random_y_squared.sqrt().unwrap().into_bigint().into();

        vm.insert_value(cell_ref_to_relocatable(x, vm), Felt252::from(x_bigint))?;
        vm.insert_value(cell_ref_to_relocatable(y, vm), Felt252::from(y_bigint))?;

        Ok(())
    }

    fn alloc_felt_256_dict(
        &self,
        vm: &mut VirtualMachine,
        segment_arena_ptr: &ResOperand,
        exec_scopes: &mut ExecutionScopes,
    ) -> Result<(), HintError> {
        let (cell, base_offset) = extract_buffer(segment_arena_ptr)?;
        let dict_manager_address = get_ptr(vm, cell, &base_offset)?;

        let n_dicts = vm
            .get_integer((dict_manager_address - 2)?)?
            .into_owned()
            .to_usize()
            .expect("Number of dictionaries too large.");
        let dict_infos_base = vm.get_relocatable((dict_manager_address - 3)?)?;

        let dict_manager_exec_scope =
            match exec_scopes.get_mut_ref::<DictManagerExecScope>("dict_manager_exec_scope") {
                Ok(dict_manager_exec_scope) => dict_manager_exec_scope,
                Err(_) => {
                    exec_scopes.assign_or_update_variable(
                        "dict_manager_exec_scope",
                        Box::<DictManagerExecScope>::default(),
                    );
                    exec_scopes.get_mut_ref::<DictManagerExecScope>("dict_manager_exec_scope")?
                }
            };
        let new_dict_segment = dict_manager_exec_scope.new_default_dict(vm);
        vm.insert_value((dict_infos_base + 3 * n_dicts)?, new_dict_segment)?;

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
            Hint::Core(CoreHint::AllocSegment { dst }) => self.alloc_segment(vm, dst),

            Hint::Core(CoreHint::TestLessThan { lhs, rhs, dst }) => {
                self.test_less_than(vm, lhs, rhs, dst)
            }

            Hint::Core(CoreHint::TestLessThanOrEqual { lhs, rhs, dst }) => {
                self.test_less_than_or_equal(vm, lhs, rhs, dst)
            }

            Hint::Core(CoreHint::GetSegmentArenaIndex {
                dict_end_ptr,
                dict_index,
            }) => self.get_segment_arena_index(vm, exec_scopes, dict_end_ptr, dict_index),

            Hint::Core(CoreHint::DivMod {
                lhs,
                rhs,
                quotient,
                remainder,
            }) => self.div_mod(vm, lhs, rhs, quotient, remainder),

            Hint::Core(CoreHint::Uint256DivMod {
                dividend_low,
                dividend_high,
                divisor_low,
                divisor_high,
                quotient0,
                quotient1,
                divisor0,
                divisor1,
                extra0,
                extra1,
                remainder_low,
                remainder_high,
            }) => self.uint256_div_mod(
                vm,
                dividend_low,
                dividend_high,
                divisor_low,
                divisor_high,
                quotient0,
                quotient1,
                divisor0,
                divisor1,
                extra0,
                extra1,
                remainder_low,
                remainder_high,
            ),
            Hint::Core(CoreHint::AssertLeIsFirstArcExcluded {
                skip_exclude_a_flag,
            }) => self.assert_le_if_first_arc_exclueded(vm, skip_exclude_a_flag, exec_scopes),

            Hint::Core(CoreHint::AssertLeIsSecondArcExcluded {
                skip_exclude_b_minus_a,
            }) => self.assert_le_is_second_excluded(vm, skip_exclude_b_minus_a, exec_scopes),

            Hint::Core(CoreHint::LinearSplit {
                value,
                scalar,
                max_x,
                x,
                y,
            }) => self.linear_split(vm, value, scalar, max_x, x, y),

            Hint::Core(CoreHint::SquareRoot { value, dst }) => self.square_root(vm, value, dst),

            Hint::Core(CoreHint::AllocFelt252Dict { segment_arena_ptr }) => {
                self.alloc_felt_256_dict(vm, segment_arena_ptr, exec_scopes)
            }

            Hint::Core(CoreHint::AssertLeFindSmallArcs {
                range_check_ptr,
                a,
                b,
            }) => self.assert_le_find_small_arcs(vm, exec_scopes, range_check_ptr, a, b),

            Hint::Core(CoreHint::RandomEcPoint { x, y }) => self.random_ec_point(vm, x, y),

            _ => todo!(),
        }
    }
}
