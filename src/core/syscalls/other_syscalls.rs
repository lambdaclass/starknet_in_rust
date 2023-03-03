use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use cairo_rs::{
    hint_processor::builtin_hint_processor::{
        builtin_hint_processor_definition::HintProcessorData,
        hint_utils::{get_integer_from_var_name, insert_value_from_var_name},
    },
    vm::vm_core::VirtualMachine,
};
use felt::Felt;
use num_traits::{One, Zero};
use std::collections::HashMap;

pub fn addr_bound_prime(
    vm: &mut VirtualMachine,
    hint_data: &HintProcessorData,
    constants: &HashMap<String, Felt>,
) -> Result<(), SyscallHandlerError> {
    let addr_bound = constants
        .get("starkware.starknet.common.storage.ADDR_BOUND")
        .unwrap();

    // TODO: Check asserts? (they should be constant)
    // "assert (2**250 < ADDR_BOUND <= 2**251) and (2 * 2**250 < PRIME) and (",
    // "        ADDR_BOUND * 2 > PRIME), \\",
    // "    'normalize_address() cannot be used with the current constants.'",

    let addr =
        get_integer_from_var_name("addr", vm, &hint_data.ids_data, &hint_data.ap_tracking).unwrap();
    let is_small = if addr.as_ref() < addr_bound {
        Felt::one()
    } else {
        Felt::zero()
    };

    insert_value_from_var_name(
        "is_small",
        is_small,
        vm,
        &hint_data.ids_data,
        &hint_data.ap_tracking,
    )
    .unwrap();

    Ok(())
}

pub fn addr_is_250(
    vm: &mut VirtualMachine,
    hint_data: &HintProcessorData,
    _constants: &HashMap<String, Felt>,
) -> Result<(), SyscallHandlerError> {
    let addr =
        get_integer_from_var_name("addr", vm, &hint_data.ids_data, &hint_data.ap_tracking).unwrap();
    let is_250 = if addr.as_ref().bits() <= 250 {
        Felt::one()
    } else {
        Felt::zero()
    };

    insert_value_from_var_name(
        "is_250",
        is_250,
        vm,
        &hint_data.ids_data,
        &hint_data.ap_tracking,
    )
    .unwrap();

    Ok(())
}
