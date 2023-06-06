use crate::core::errors::contract_address_errors::ContractAddressError;
use cairo_lang_starknet::{
    contract::starknet_keccak, contract_class::ContractClass as SierraContractClass,
};
use cairo_vm::felt::Felt252;
use starknet_contract_class::{ContractEntryPoint, EntryPointType};
use starknet_crypto::{poseidon_hash_many, FieldElement};

const CONTRACT_CLASS_VERSION: &[u8] = b"CONTRACT_CLASS_V0.1.0";

// ---------------------------------
//  Version 2 functions and structs
// ---------------------------------

fn get_contract_entry_points_hashed(
    contract_class: &SierraContractClass,
    entry_point_type: &EntryPointType,
) -> Result<FieldElement, ContractAddressError> {
    let contract_entry_points = get_contract_entry_points(contract_class, entry_point_type)?;

    // for each entry_point, we need to store 2 FieldElements: selector and offset.
    let mut entry_points_flatted = Vec::with_capacity(contract_entry_points.len() * 2);

    for entry_point in contract_entry_points {
        entry_points_flatted.push(
            FieldElement::from_bytes_be(&entry_point.selector().to_be_bytes()).map_err(|_err| {
                ContractAddressError::Cast("Felt252".to_string(), "FieldElement".to_string())
            })?,
        );
        entry_points_flatted.push(FieldElement::from(entry_point.offset()));
    }

    Ok(poseidon_hash_many(&entry_points_flatted))
}

pub fn compute_sierra_class_hash(
    contract_class: &SierraContractClass,
) -> Result<Felt252, ContractAddressError> {
    let api_version =
        FieldElement::from_bytes_be(&Felt252::from_bytes_be(CONTRACT_CLASS_VERSION).to_be_bytes())
            .map_err(|_err| {
                ContractAddressError::Cast("Felt252".to_string(), "FieldElement".to_string())
            })?;

    // Entrypoints by type, hashed.
    let external_functions =
        get_contract_entry_points_hashed(contract_class, &EntryPointType::External)?;
    let l1_handlers = get_contract_entry_points_hashed(contract_class, &EntryPointType::L1Handler)?;
    let constructors =
        get_contract_entry_points_hashed(contract_class, &EntryPointType::Constructor)?;

    // Hash abi_hash.
    let abi = contract_class
        .abi
        .clone()
        .ok_or(ContractAddressError::MissingAbi)?
        .json();

    let abi_hash =
        FieldElement::from_bytes_be(&Felt252::from(starknet_keccak(abi.as_bytes())).to_be_bytes())
            .map_err(|_err| {
                ContractAddressError::Cast("Felt252".to_string(), "FieldElement".to_string())
            })?;

    let mut sierra_program_vector = Vec::with_capacity(contract_class.sierra_program.len());
    for number in &contract_class.sierra_program {
        sierra_program_vector.push(
            FieldElement::from_bytes_be(&Felt252::from(number.value.clone()).to_be_bytes())
                .map_err(|_err| {
                    ContractAddressError::Cast("Felt252".to_string(), "FieldElement".to_string())
                })?,
        );
    }

    // Hash Sierra program.
    let sierra_program_ptr = poseidon_hash_many(&sierra_program_vector);

    let flatted_contract_class = vec![
        api_version,
        external_functions,
        l1_handlers,
        constructors,
        abi_hash,
        sierra_program_ptr,
    ];

    Ok(Felt252::from_bytes_be(
        &poseidon_hash_many(&flatted_contract_class).to_bytes_be(),
    ))
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
        .map(|entry_point| {
            ContractEntryPoint::new(
                entry_point.selector.clone().into(),
                entry_point.function_idx,
            )
        })
        .collect())
}
