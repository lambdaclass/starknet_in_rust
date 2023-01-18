use cairo_rs::{
    hint_processor::{
        self, builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
        hint_processor_definition::HintProcessor,
    },
    serde::deserialize_program::Identifier,
    types::{program::Program, relocatable::MaybeRelocatable},
    vm::{
        self,
        runners::{builtin_runner::BuiltinRunner, cairo_runner::CairoRunner},
        vm_core::VirtualMachine,
    },
};
use felt::{Felt, FeltOps};
use num_traits::{pow, Num};

use crate::{
    core::errors::contract_address_errors::ContractAddressError,
    hash_utils::calculate_contract_address_from_hash,
    services::api::contract_class::{ContractClass, ContractEntryPoint, EntryPointType},
    utils::Address,
};
use sha3::{Digest, Keccak256};

/// Calculates the contract address in the starkNet network - a unique identifier of the contract.
/// The contract address is a hash chain of the following information:
///     1. Prefix.
///     2. Deployer address.
///     3. Salt.
///     4. Class hash.
/// To avoid exceeding the maximum address we take modulus L2_ADDRESS_UPPER_BOUND of the above
/// result.
pub(crate) fn calculate_contract_address(
    salt: &Felt,
    contract_class: &ContractClass,
    constructor_calldata: &[Felt],
    deployer_address: Address,
) -> Result<Felt, ContractAddressError> {
    let class_hash = compute_class_hash(contract_class)?;

    calculate_contract_address_from_hash(salt, &class_hash, constructor_calldata, deployer_address)
        .map_err(|err| ContractAddressError::ContractAddressFromHash(err.to_string()))
}

fn load_program() -> Result<Program, ContractAddressError> {
    Program::from_file(Path::new("contracts.json"), None)
        .map_err(|err| ContractAddressError::Program(err.to_string()))
}

fn get_contract_entry_points(
    contract_class: &ContractClass,
    entry_point_type: &EntryPointType,
) -> Result<Vec<ContractEntryPoint>, ContractAddressError> {
    let program_length = contract_class.program.data.len();
    let entry_points = contract_class
        .entry_points_by_type
        .get(entry_point_type)
        .ok_or(ContractAddressError::NoneExistingEntryPointType)?;

    for entry_point in entry_points {
        if (Felt::from(0) <= entry_point.offset) && (entry_point.offset < program_length.into()) {
            return Err(ContractAddressError::InvalidOffset(
                entry_point.offset.to_string(),
            ));
        }
    }

    Ok(entry_points
        .iter()
        .map(|entry_point| ContractEntryPoint {
            offset: entry_point.offset.clone(),
            selector: entry_point.selector.clone(),
        })
        .collect())
}

// MASK_250 = 2 ** 250 - 1
/// Instead of doing a Mask with 250 bits, we are only masking the most significant byte.
pub const MASK_3: u8 = 3;

/// A variant of eth-keccak that computes a value that fits in a StarkNet field element.
fn starknet_keccak(data: &[u8]) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut finalized_hash = hasher.finalize();
    let mut hashed_slice: &[u8] = finalized_hash.as_slice();

    // This is the same than doing a mask 3 only with the most significant byte.
    // and then copying the other values.
    let res = hashed_slice[0] & MASK_3;
    finalized_hash[0] = res;
    Felt::from_bytes_be(finalized_hash.as_slice())
}

/// Computes the hash of the contract class, including hints.
/// We are not supporting backward compatibility now.
fn compute_hinted_class_hash(contract_class: &ContractClass) -> Felt {
    let keccak_input =
        r#"{"abi": contract_class.abi, "program": contract_class.program}"#.as_bytes();
    starknet_keccak(keccak_input)
}

/// Returns the serialization of a contract as a list of field elements.
fn get_contract_class_struct(
    identifiers: &HashMap<String, Identifier>,
    contract_class: &ContractClass,
) -> Result<StructContractClass, ContractAddressError> {
    let api_version = identifiers
        .get("API_VERSION")
        .ok_or_else(|| ContractAddressError::MissingIdentifier("API_VERSION".to_string()))?;

    let external_functions = get_contract_entry_points(contract_class, &EntryPointType::External)?;
    let l1_handlers = get_contract_entry_points(contract_class, &EntryPointType::L1Handler)?;
    let constructors = get_contract_entry_points(contract_class, &EntryPointType::Constructor)?;

    let builtin_list = &contract_class.program.builtins;

    Ok(StructContractClass {
        api_version: api_version
            .value
            .as_ref()
            .ok_or(ContractAddressError::NoneApiVersion)?
            .to_owned(),
        n_external_functions: external_functions.len(),
        external_functions,
        n_l1_handlers: l1_handlers.len(),
        l1_handlers,
        n_constructors: constructors.len(),
        constructors,
        n_builtins: builtin_list.len(),
        builtin_list: builtin_list.to_vec(),
        hinted_class_hash: compute_hinted_class_hash(contract_class),
        bytecode_length: contract_class.program.data.len(),
        bytecode_ptr: contract_class.program.data.clone(),
    })
}

// TODO: think about a new name for this struct (ContractClass already exists)
struct StructContractClass {
    api_version: Felt,
    n_external_functions: usize,
    external_functions: Vec<ContractEntryPoint>,
    n_l1_handlers: usize,
    l1_handlers: Vec<ContractEntryPoint>,
    n_constructors: usize,
    constructors: Vec<ContractEntryPoint>,
    n_builtins: usize,
    builtin_list: Vec<String>,
    hinted_class_hash: Felt,
    bytecode_length: usize,
    bytecode_ptr: Vec<MaybeRelocatable>,
}

use std::{collections::HashMap, hash::Hash, path::Path};

pub(crate) fn compute_class_hash(
    contract_class: &ContractClass,
) -> Result<Felt, ContractAddressError> {
    // Since we are not using a cache, this function replace compute_class_hash_inner.
    let program = load_program()?;
    let contract_class_struct = get_contract_class_struct(&program.identifiers, contract_class);

    let mut vm = VirtualMachine::new(false);
    let mut runner = CairoRunner::new(&program, "all", false)
        .map_err(|err| ContractAddressError::CairoRunner(err.to_string()))?;
    runner.initialize_function_runner(&mut vm);

    let mut hint_processor = BuiltinHintProcessor::new_empty();

    // 188 is the entrypoint since is the __main__.class_hash function in our compiled program.
    // TODO: Looks like we can get this value from the identifier, but the value is a Felt.
    // We need to cast that into a usize.
    // let entrypoint = program.identifiers.get("class_hash").unwrap();

    runner.run_from_entrypoint(
        188,
        Vec::new(),
        false,
        false,
        false,
        &mut vm,
        &mut hint_processor,
    );

    Ok(vm
        .get_return_values(2)
        .map_err(|err| ContractAddressError::Memory(err.to_string()))?
        .get(1)
        .ok_or(ContractAddressError::IndexOutOfRange)?
        .get_int_ref()
        .map_err(|_| ContractAddressError::ExpectedInteger)?
        .clone())
}
