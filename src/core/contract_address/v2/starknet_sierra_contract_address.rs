use std::{collections::HashMap, path::Path};

use cairo_lang_starknet::{abi::Contract, contract_class::ContractClass as SierraContractClass};
use cairo_rs::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    serde::deserialize_program::Identifier,
    types::{program::Program, relocatable::MaybeRelocatable},
    vm::{runners::cairo_runner::CairoRunner, vm_core::VirtualMachine},
};
use felt::Felt252;

use crate::{
    core::errors::contract_address_errors::ContractAddressError,
    services::api::contract_class::{ContractEntryPoint, EntryPointType},
};

// ---------------------------------
//  Version 2 functions and structs
// ---------------------------------

struct SierraStructContractClass {
    api_version: MaybeRelocatable,
    n_external_functions: MaybeRelocatable,
    external_functions: Vec<ContractEntryPoint>,
    n_l1_handlers: MaybeRelocatable,
    l1_handlers: Vec<ContractEntryPoint>,
    n_constructors: MaybeRelocatable,
    constructors: Vec<ContractEntryPoint>,
    abi_hash: Option<Contract>,
    sierra_program_length: MaybeRelocatable,
    sierra_program_ptr: Vec<MaybeRelocatable>,
}

fn load_program() -> Result<Program, ContractAddressError> {
    Ok(Program::from_file(
        Path::new("cairo_programs/contracts.json"),
        None,
    )?)
}

// TODO: Maybe this could be hard-coded (to avoid returning a result)?
pub fn compute_sierra_class_hash(
    contract_class: &SierraContractClass,
) -> Result<Felt252, ContractAddressError> {
    // Since we are not using a cache, this function replace compute_class_hash_inner.
    let program = load_program()?;
    let contract_class_struct =
        &get_sierra_contract_class_struct(&program.identifiers, contract_class)?.into();

    let mut vm = VirtualMachine::new(false);
    let mut runner = CairoRunner::new(&program, "all_cairo", false)?;
    runner.initialize_function_runner(&mut vm)?;
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    // 188 is the entrypoint since is the __main__.class_hash function in our compiled program identifier.
    // TODO: Looks like we can get this value from the identifier, but the value is a Felt252.
    // We need to cast that into a usize.
    // let entrypoint = program.identifiers.get("__main__.class_hash").unwrap().pc.unwrap();
    let hash_base: MaybeRelocatable = runner.add_additional_hash_builtin(&mut vm).into();

    runner.run_from_entrypoint(
        188,
        &[&hash_base.into(), contract_class_struct],
        true,
        &mut vm,
        &mut hint_processor,
    )?;

    match vm.get_return_values(2)?.get(1) {
        Some(MaybeRelocatable::Int(felt)) => Ok(felt.clone()),
        _ => Err(ContractAddressError::IndexOutOfRange),
    }
}

fn get_contract_entry_points(
    contract_class: &SierraContractClass,
    entry_point_type: &EntryPointType,
) -> Result<Vec<ContractEntryPoint>, ContractAddressError> {
    let program_length = contract_class.sierra_program.len();

    let entry_points = match entry_point_type {
        EntryPointType::Constructor => contract_class.entry_points_by_type.constructor,
        EntryPointType::External => contract_class.entry_points_by_type.external,
        EntryPointType::L1Handler => contract_class.entry_points_by_type.l1_handler,
    };

    let program_len = program_length;
    for entry_point in entry_points {
        if entry_point.function_idx > program_len {
            return Err(ContractAddressError::InvalidOffset(
                entry_point.function_idx,
            ));
        }
    }

    Ok(entry_points
        .iter()
        .map(|entry_point| ContractEntryPoint {
            offset: entry_point.function_idx,
            selector: entry_point.selector.clone().into(),
        })
        .collect())
}

// Returns the serialization of a contract as a list of field elements.
fn get_sierra_contract_class_struct(
    identifiers: &HashMap<String, Identifier>,
    contract_class: &SierraContractClass,
) -> Result<SierraStructContractClass, ContractAddressError> {
    let api_version = identifiers.get("__main__.API_VERSION").ok_or_else(|| {
        ContractAddressError::MissingIdentifier("__main__.API_VERSION".to_string())
    })?;
    let external_functions = get_contract_entry_points(contract_class, &EntryPointType::External)?;
    let l1_handlers = get_contract_entry_points(contract_class, &EntryPointType::L1Handler)?;
    let constructors = get_contract_entry_points(contract_class, &EntryPointType::Constructor)?;
    let abi_hash = contract_class.abi;

    let sierra_program_ptr = contract_class
        .sierra_program
        .iter()
        .map(|b| Felt252::from(b.value).into())
        .collect();

    Ok(SierraStructContractClass {
        api_version: api_version
            .value
            .as_ref()
            .ok_or(ContractAddressError::NoneApiVersion)?
            .to_owned()
            .into(),
        n_external_functions: Felt252::from(external_functions.len()).into(),
        external_functions,
        n_l1_handlers: Felt252::from(l1_handlers.len()).into(),
        l1_handlers,
        abi_hash,
        n_constructors: Felt252::from(constructors.len()).into(),
        constructors,
        sierra_program_length: Felt252::from(contract_class.sierra_program.len()).into(),
        sierra_program_ptr,
    })
}
