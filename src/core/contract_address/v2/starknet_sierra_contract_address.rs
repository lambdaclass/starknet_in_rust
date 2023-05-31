use cairo_lang_starknet::{
    contract::starknet_keccak, contract_class::ContractClass as SierraContractClass,
};
use cairo_vm::felt::Felt252;
use cairo_vm::serde::deserialize_program::BuiltinName;
use cairo_vm::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    serde::deserialize_program::Identifier,
    types::{program::Program, relocatable::MaybeRelocatable},
    vm::{
        runners::{
            builtin_runner::BuiltinRunner,
            cairo_runner::{CairoArg, CairoRunner},
        },
        vm_core::VirtualMachine,
    },
};

use std::path::Path;

use crate::hash_utils::compute_poseidon_hash_on_elements;
use crate::{
    core::errors::contract_address_errors::ContractAddressError,
    services::api::contract_classes::deprecated_contract_class::{
        ContractEntryPoint, EntryPointType,
    },
};

const CONTRACT_CLASS_VERSION: &str = "CONTRACT_CLASS_V0.1.0";

// ---------------------------------
//  Version 2 functions and structs
// ---------------------------------

struct SierraStructContractClass {
    contract_class_version_iden: MaybeRelocatable,
    n_external_functions: MaybeRelocatable,
    external_functions: Vec<ContractEntryPoint>,
    n_l1_handlers: MaybeRelocatable,
    l1_handlers: Vec<ContractEntryPoint>,
    n_constructors: MaybeRelocatable,
    constructors: Vec<ContractEntryPoint>,
    abi_hash: Felt252,
    sierra_program_length: MaybeRelocatable,
    sierra_program_ptr: Vec<MaybeRelocatable>,
}

fn flat_into_maybe_relocs(contract_entrypoints: Vec<ContractEntryPoint>) -> Vec<MaybeRelocatable> {
    contract_entrypoints
        .iter()
        .flat_map::<Vec<MaybeRelocatable>, _>(|contract_entrypoint| contract_entrypoint.into())
        .collect::<Vec<MaybeRelocatable>>()
}

impl From<SierraStructContractClass> for CairoArg {
    fn from(contract_class: SierraStructContractClass) -> Self {
        let external_functions_flatted = flat_into_maybe_relocs(contract_class.external_functions);
        let l1_handlers_flatted = flat_into_maybe_relocs(contract_class.l1_handlers);
        let constructors_flatted = flat_into_maybe_relocs(contract_class.constructors);

        let result = vec![
            CairoArg::Single(contract_class.contract_class_version_iden),
            CairoArg::Single(contract_class.n_external_functions),
            CairoArg::Array(external_functions_flatted),
            CairoArg::Single(contract_class.n_l1_handlers),
            CairoArg::Array(l1_handlers_flatted),
            CairoArg::Single(contract_class.n_constructors),
            CairoArg::Array(constructors_flatted),
            CairoArg::Single(contract_class.abi_hash.into()),
            CairoArg::Single(contract_class.sierra_program_length),
            CairoArg::Array(contract_class.sierra_program_ptr),
        ];
        CairoArg::Composed(result)
    }
}

fn load_program() -> Result<Program, ContractAddressError> {
    Ok(Program::from_file(
        Path::new("cairo_programs/contract_class.json"),
        None,
    )?)
}

fn get_contract_entry_points_hashed(
    contract_class: &SierraContractClass,
    entry_point_type: &EntryPointType,
) -> Result<Felt252, ContractAddressError> {
    Ok(compute_poseidon_hash_on_elements(
        &get_contract_entry_points(contract_class, entry_point_type)?
            .iter()
            .flat_map(|contract_entry_point| {
                vec![
                    contract_entry_point.selector.clone(),
                    Felt252::from(contract_entry_point.offset),
                ]
            })
            .collect::<Vec<Felt252>>(),
    )?)
}

pub fn compute_sierra_class_hash_refactorized(
    contract_class: &SierraContractClass,
) -> Result<Felt252, ContractAddressError> {
    // hash_update_single(item=contract_class.contract_class_version); -> update_singlea means unhashed
    let api_version = Felt252::from_bytes_be(CONTRACT_CLASS_VERSION.as_bytes());

    // // Hash external entry points.
    // hash_update_with_nested_hash(
    //     data_ptr=contract_class.external_functions,
    //     data_length=contract_class.n_external_functions * ContractEntryPoint.SIZE,
    // );

    // // Hash L1 handler entry points.
    // hash_update_with_nested_hash(
    //     data_ptr=contract_class.l1_handlers,
    //     data_length=contract_class.n_l1_handlers * ContractEntryPoint.SIZE,
    // );

    // // Hash constructor entry points.
    // hash_update_with_nested_hash(
    //     data_ptr=contract_class.constructors,
    //     data_length=contract_class.n_constructors * ContractEntryPoint.SIZE,
    // );

    // Entrypoints by type, hashed.
    let external_functions =
        get_contract_entry_points_hashed(contract_class, &EntryPointType::External)?;
    let l1_handlers = get_contract_entry_points_hashed(contract_class, &EntryPointType::L1Handler)?;
    let constructors =
        get_contract_entry_points_hashed(contract_class, &EntryPointType::Constructor)?;

    // // Hash abi_hash.
    // hash_update_single(item=contract_class.abi_hash);
    let abi = contract_class
        .abi
        .clone()
        .ok_or(ContractAddressError::MissingAbi)?
        .json();

    let abi_hash = Felt252::from(starknet_keccak(abi.as_bytes()));

    // // Hash Sierra program.
    // hash_update_with_nested_hash(
    //     data_ptr=contract_class.sierra_program_ptr,
    //     data_length=contract_class.sierra_program_length,
    // );

    let sierra_program_ptr = compute_poseidon_hash_on_elements(
        &contract_class
            .sierra_program
            .iter()
            .map(|b| Felt252::from(b.value.clone()))
            .collect::<Vec<Felt252>>(),
    )?;

    let flatted_contract_class: Vec<Felt252> = vec![
        api_version,
        external_functions,
        l1_handlers,
        constructors,
        abi_hash,
        sierra_program_ptr,
    ];

    Ok(compute_poseidon_hash_on_elements(&flatted_contract_class)?)
}

// TODO: Maybe this could be hard-coded (to avoid returning a result)?
pub fn compute_sierra_class_hash(
    contract_class: &SierraContractClass,
) -> Result<Felt252, ContractAddressError> {
    // Since we are not using a cache, this function replace compute_class_hash_inner.
    let program = load_program()?;

    let contract_class_version_iden = program
        .get_identifier("__main__.CONTRACT_CLASS_VERSION")
        .ok_or_else(|| {
            ContractAddressError::MissingIdentifier("__main__.CONTRACT_CLASS_VERSION".to_string())
        })?;

    let contract_class_struct =
        &get_sierra_contract_class_struct(contract_class_version_iden, contract_class)?.into();

    let mut vm = VirtualMachine::new(false);
    let mut runner = CairoRunner::new(&program, "all_cairo", false)?;

    runner.initialize_function_runner_cairo_1(
        &mut vm,
        &program
            .iter_builtins()
            .cloned()
            .collect::<Vec<BuiltinName>>(),
    )?;

    let mut hint_processor = BuiltinHintProcessor::new_empty();
    let entrypoint = program
        .get_identifier("__main__.class_hash")
        .ok_or_else(|| ContractAddressError::MissingIdentifier("__main__.class_hash".to_string()))?
        .pc
        .unwrap();

    // Poseidon base needs to be passed on to the runner in order to enable it to compute it correctly
    let poseidon_runner = vm
        .get_builtin_runners()
        .iter()
        .find(|x| matches!(x, BuiltinRunner::Poseidon(_)))
        .unwrap();
    let poseidon_base = MaybeRelocatable::from((poseidon_runner.base() as isize, 0));

    runner.run_from_entrypoint(
        entrypoint,
        &[&poseidon_base.into(), contract_class_struct],
        true,
        None,
        &mut vm,
        &mut hint_processor,
    )?;

    match vm.get_return_values(2)?.get(1) {
        Some(MaybeRelocatable::Int(felt)) => {
            assert_eq!(
                felt.clone(),
                compute_sierra_class_hash_refactorized(contract_class).unwrap()
            );
            Ok(felt.clone())
        }
        _ => Err(ContractAddressError::IndexOutOfRange),
    }
}

fn get_contract_entry_points(
    contract_class: &SierraContractClass,
    entry_point_type: &EntryPointType,
) -> Result<Vec<ContractEntryPoint>, ContractAddressError> {
    let program_length = contract_class.sierra_program.len();

    let entry_points = match entry_point_type {
        EntryPointType::Constructor => contract_class.entry_points_by_type.constructor.clone(),
        EntryPointType::External => contract_class.entry_points_by_type.external.clone(),
        EntryPointType::L1Handler => contract_class.entry_points_by_type.l1_handler.clone(),
    };

    let program_len = program_length;
    for entry_point in &entry_points {
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
    contract_class_version_identifier: &Identifier,
    contract_class: &SierraContractClass,
) -> Result<SierraStructContractClass, ContractAddressError> {
    let external_functions = get_contract_entry_points(contract_class, &EntryPointType::External)?;
    let l1_handlers = get_contract_entry_points(contract_class, &EntryPointType::L1Handler)?;
    let constructors = get_contract_entry_points(contract_class, &EntryPointType::Constructor)?;
    let abi = contract_class
        .abi
        .clone()
        .ok_or(ContractAddressError::MissingAbi)?
        .json();

    let abi_hash = Felt252::from(starknet_keccak(abi.as_bytes()));
    let sierra_program_ptr = contract_class
        .sierra_program
        .iter()
        .map(|b| Felt252::from(b.value.clone()).into())
        .collect();

    let contract_class_version_iden = contract_class_version_identifier
        .value
        .as_ref()
        .ok_or(ContractAddressError::NoneApiVersion)?
        .to_owned()
        .into();

    Ok(SierraStructContractClass {
        contract_class_version_iden,
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
