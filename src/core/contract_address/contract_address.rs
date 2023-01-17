use cairo_rs::{types::program::Program, vm::runners::{cairo_runner::CairoRunner, builtin_runner::BuiltinRunner}, serde::deserialize_program::Identifier};
use num_bigint::BigInt;
use num_traits::pow;

use crate::{
    core::errors::syscall_handler_errors::SyscallHandlerError,
    hash_utils::calculate_contract_address_from_hash, services::api::contract_class::{ContractClass, EntryPointType, ContractEntryPoint},
};
use sha3::{Digest, Keccak256};

pub(crate) fn calculate_contract_address(
    salt: &BigInt,
    contract_class: &ContractClass,
    constructor_calldata: &[BigInt],
    deployer_address: u64,
) -> Result<BigInt, SyscallHandlerError> {
    // TODO: maybe this is not the right error type.
    let class_hash = compute_class_hash(contract_class).unwrap();

    calculate_contract_address_from_hash(salt, &class_hash, constructor_calldata, deployer_address)
}

fn load_program() -> Program {
    // compile_cairo_files(
    //     "contracts.cairo",
    //     2**251 + 17 * 2**192 + 1, // default cairo prime
    //     //main_scope=ScopedName.from_string("starkware.starknet.core.os.contracts"),
    // )
    todo!()
}

fn get_contract_entry_points(
    contract_class: ContractClass,
    entry_point_type: EntryPointType,
) -> Result<Vec<ContractEntryPoint>, SyscallHandlerError> {
    
    let program_length = contract_class.program.data.len();
    let entry_points = contract_class.entry_points_by_type.get(&entry_point_type).unwrap();

    for entry_point in entry_points {
        if (BigInt::from(0) <= entry_point.offset) && (entry_point.offset < program_length.into()) {
            return Err(SyscallHandlerError::BigintToU64Fail); 
            // TODO: change this error to:
            // f"Invalid entry point offset {entry_point.offset}, len(program_data)={program_length}."
        }
    }

    Ok(entry_points.iter().map(|entry_point| ContractEntryPoint {offset: entry_point.offset, selector: entry_point.selector}).collect())
}

const MASK_250: BigInt = BigInt::from(pow(2,250) - 1);

/// A variant of eth-keccak that computes a value that fits in a StarkNet field element.
fn starknet_keccak(data: &mut Vec<u8>) -> u64 {
    let mut hasher = Keccak256::new();
    hasher.update(data);

    let hashed = hasher.finalize();

    BigInt::from_bytes_be(sign, hashed);
    from_bytes(keccak(data)) & MASK_250
}

/// Computes the hash of the contract class, including hints.
fn compute_hinted_class_hash(contract_class: ContractClass) -> BigInt {
    // no vamos a hacer esto, no tenemos debug info 
    let mut program_without_debug_info = contract_class.program.clone();
    // program_without_debug_info.debug_info = false;

    // We are not supporting backward compatibility now.

    // // If compiler_version is not present, this was compiled with a compiler before version 0.10.0.
    // // Use "(a : felt)" syntax instead of "(a: felt)" so that the class hash will be the same.
    // with add_backward_compatibility_space(contract_class.program.compiler_version is None):
    //     dumped_program = program_without_debug_info.dump()

    // if len(dumped_program["attributes"]) == 0:
    //     // Remove attributes field from raw dictionary, for hash backward compatibility of
    //     // contracts deployed prior to adding this feature.
    //     del dumped_program["attributes"]
    // else:
    //     // Remove accessible_scopes and flow_tracking_data fields from raw dictionary, for hash
    //     // backward compatibility of contracts deployed prior to adding this feature.
    //     for attr in dumped_program["attributes"]:
    //         if len(attr["accessible_scopes"]) == 0:
    //             del attr["accessible_scopes"]
    //         if attr["flow_tracking_data"] is None:
    //             del attr["flow_tracking_data"]

    // let mut hashmap_input = HashMap::new();
    // hashmap_input.insert("program", program_without_debug_info);
    // hashmap_input.insert("abi", contract_class.abi);
    
     //hashmap_input.dumps(input_to_hash, sort_keys=True).encode()
    starknet_keccak(r#"{"program": program_without_debug_info, "abi": contract_class.abi}"#)
}

/// Returns the serialization of a contract as a list of field elements.
fn get_contract_class_struct(
    identifiers: &HashMap<String, Identifier>, contract_class: ContractClass
) -> Result<StructContractClass, SyscallHandlerError> {
    // usar directamente los de rust
    // structs = CairoStructFactory(
    //     identifiers=identifiers,
    //     additional_imports=[
    //         "starkware.starknet.core.os.contracts.ContractClass",
    //         "starkware.starknet.core.os.contracts.ContractEntryPoint",
    //     ],
    // ).structs
    

    let api_version = identifiers.get("API_VERSION").ok_or(SyscallHandlerError::MissingIdentifiers)?;

    let external_functions = get_contract_entry_points(contract_class, EntryPointType::External).unwrap();
    let l1_handlers = get_contract_entry_points(contract_class, EntryPointType::L1Handler).unwrap();
    let constructors = get_contract_entry_points(contract_class, EntryPointType::Constructor).unwrap();

    // let flat_external_functions, flat_l1_handlers, flat_constructors = (
    //     list(itertools.chain.from_iterable(entry_points))
    //     for entry_points in (external_functions, l1_handlers, constructors)
    // )

    let builtin_list = contract_class.program.builtins;
    
    // este contract class es distinto, solamente guarda los campos.
    Ok(StructContractClass {
        api_version: api_version.value.unwrap(),
        n_external_functions: external_functions.len(),
        external_functions,
        n_l1_handlers: l1_handlers.len(),
        l1_handlers,
        n_constructors: constructors.len(),
        constructors,
        n_builtins: builtin_list.len(),
        builtin_list,
        hinted_class_hash: compute_hinted_class_hash(contract_class: contract_class),
        bytecode_length: contract_class.program.data.len(),
        bytecode_ptr: contract_class.program.data,
    })
}

/// This is awful, I know. Name ideas? We already have a ContractClass struct.
struct StructContractClass {
    api_version: BigInt,
    n_external_functions: usize,
    external_functions: Vec<ContractEntryPoint>, 
    n_l1_handlers: usize,
    l1_handlers: Vec<ContractEntryPoint>,
    n_constructors: usize,
    constructors: Vec<ContractEntryPoint>,
    n_builtins: usize,
    builtin_list: Vec<String>,
    hinted_class_hash: compute_hinted_class_hash(contract_class=contract_class),
    bytecode_length: usize,
    bytecode_ptr:  Vec<MaybeRelocatable,
}

fn compute_class_hash_inner(
    contract_class: &ContractClass
) -> BigInt{
    let program = load_program();
    let contract_class_struct = get_contract_class_struct(
        program.identifiers, contract_class
    );
    
    let runner = CairoRunner::new(&program, "all", false).unwrap();

    // we are using the default one, since the only difference is the name
    // let hash_builtin = HashBuiltinRunner(
        //     name="custom_hasher", included=True, ratio=32, hash_func=hash_func
    // )
    // runner.builtin_runners["hash_builtin"] = hash_builtin
    runner.run_until_pc(address, vm, hint_processor)
    runner.run(
        "starkware.starknet.core.os.contracts.class_hash",
        hash_ptr=hash_builtin.base,
        contract_class=contract_class_struct,
        use_full_name=True,
        verify_secure=False,
    );
    let _, class_hash = runner.get_return_values(2);
    class_hash
}

use std::{collections::HashMap, hash::Hash};

pub const CLASS_HASH_CACHE_CTX_VAR: HashMap<&str, Option<usize>> = {
    let ctx = HashMap::new();
    ctx.insert("class_hash_cache", None);
    ctx
};

pub(crate) fn compute_class_hash(
    contract_class: &ContractClass,
) -> Result<BigInt, SyscallHandlerError> {
    // TODO: maybe this is not the right error type.
    // We are replacing this line with a HashMap
    let cache = CLASS_HASH_CACHE_CTX_VAR.get();

    if cache.is_none() {
        return compute_class_hash_inner(contract_class);
    }

    let contract_class_bytes = contract_class.dumps(sort_keys = True).encode();
    let key = (starknet_keccak(data = contract_class_bytes), hash_func);

    if !cache.any(|&cached_item| key == cached_item) {
        cache.insert(
            key,
            compute_class_hash_inner(contract_class = contract_class, hash_func = hash_func),
        );
    }

    cache.get(key)
}

#[cfg(test)]
mod tests {}
