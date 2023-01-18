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
use num_traits::pow;

use crate::{
    core::errors::syscall_handler_errors::SyscallHandlerError,
    hash_utils::calculate_contract_address_from_hash,
    services::api::contract_class::{ContractClass, ContractEntryPoint, EntryPointType},
    utils::Address,
};
use sha3::{Digest, Keccak256};

pub(crate) fn calculate_contract_address(
    salt: &Felt,
    contract_class: &ContractClass,
    constructor_calldata: &[Felt],
    deployer_address: Address,
) -> Result<Felt, SyscallHandlerError> {
    // TODO: remove unwrap.
    let class_hash = compute_class_hash(contract_class).unwrap();

    calculate_contract_address_from_hash(salt, &class_hash, constructor_calldata, deployer_address)
}

fn load_program() -> Program {
    // TODO: remove unwrap.
    Program::from_file(Path::new("contracts.json"), None).unwrap()
}

fn get_contract_entry_points(
    contract_class: &ContractClass,
    entry_point_type: &EntryPointType,
) -> Result<Vec<ContractEntryPoint>, SyscallHandlerError> {
    let program_length = contract_class.program.data.len();
    let entry_points = contract_class
        .entry_points_by_type
        .get(&entry_point_type)
        .unwrap();

    for entry_point in entry_points {
        if (Felt::from(0) <= entry_point.offset) && (entry_point.offset < program_length.into()) {
            return Err(SyscallHandlerError::FeltToU64Fail);
            // TODO: change this error to:
            // f"Invalid entry point offset {entry_point.offset}, len(program_data)={program_length}."
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
pub const MASK_250: [u8; 250] = [1; 250];

/// A variant of eth-keccak that computes a value that fits in a StarkNet field element.
fn starknet_keccak(data: &[u8]) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(data);

    let hashed: &[u8] = hasher.finalize().as_slice();

    // This is the same than doing a mask 3 only with the most significant byte.
    // and then copying the other values.
    let res = hashed & &MASK_250;
    Felt::from_bytes_be(res)
}

/// Computes the hash of the contract class, including hints.
/// We are not supporting backward compatibility now.
fn compute_hinted_class_hash(contract_class: &ContractClass) -> Felt {
    let keccak_input =
        r#"{"abi": contract_class.abi, "program": contract_class.program}"#.as_bytes();
    starknet_keccak(keccak_input).into()
}

/// Returns the serialization of a contract as a list of field elements.
fn get_contract_class_struct(
    identifiers: &HashMap<String, Identifier>,
    contract_class: &ContractClass,
) -> Result<StructContractClass, SyscallHandlerError> {
    let api_version = identifiers
        .get("API_VERSION")
        .ok_or(SyscallHandlerError::MissingIdentifiers)?;

    // TODO: remove unwraps.
    let external_functions =
        get_contract_entry_points(contract_class, &EntryPointType::External).unwrap();
    let l1_handlers =
        get_contract_entry_points(contract_class, &EntryPointType::L1Handler).unwrap();
    let constructors =
        get_contract_entry_points(contract_class, &EntryPointType::Constructor).unwrap();

    let builtin_list = &contract_class.program.builtins;

    Ok(StructContractClass {
        api_version: api_version.value.as_ref().unwrap().to_owned(),
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

fn compute_class_hash_inner(contract_class: &ContractClass) -> Result<&Felt, SyscallHandlerError> {
    let program = load_program();
    let contract_class_struct = get_contract_class_struct(&program.identifiers, contract_class);

    let vm = VirtualMachine::new(false, Vec::new());
    let mut runner = CairoRunner::new(&program, "all", false).unwrap();
    runner.initialize_function_runner(&mut vm);

    let hint_processor = BuiltinHintProcessor::new_empty();

    // 188 is the entrypoint since is the __main__.class_hash function in our compiled program.
    // TODO: Looks like we can get this value from the identifier, but the value is a Felt.
    // We need to cast that into a usize.
    // let entrypoint = program.identifiers.get("class_hash").unwrap();

    // args: hash_ptr, contract_class
    runner.run_from_entrypoint(
        188,
        Vec::new(),
        false,
        false,
        false,
        &mut vm,
        &mut hint_processor,
    );

    // read_Return_Values looks quite odd, doesn't return a value.
    // TODO: change this error for a significant one.
    vm.get_return_values(0).unwrap()[0]
        .get_int_ref()
        .map_err(|_| SyscallHandlerError::ExpectedCallContract)
}

use std::{collections::HashMap, hash::Hash, path::Path};

pub(crate) fn compute_class_hash(
    contract_class: &ContractClass,
) -> Result<&Felt, SyscallHandlerError> {
    compute_class_hash_inner(contract_class)
}
