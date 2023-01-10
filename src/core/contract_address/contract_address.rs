use cairo_rs::types::program::Program;
use num_bigint::BigInt;

use crate::{
    core::errors::syscall_handler_errors::SyscallHandlerError,
    hash_utils::calculate_contract_address_from_hash, services::api::contract_class::ContractClass,
};

pub(crate) fn calculate_contract_address(
    salt: &BigInt,
    contract_class: &ContractClass,
    constructor_calldata: &[BigInt],
    deployer_address: u64,
) -> Result<BigInt, SyscallHandlerError> {
    // TODO: maybe this is not the right error type.
    let class_hash = compute_class_hash(contract_class);

    calculate_contract_address_from_hash(salt, class_hash, constructor_calldata, deployer_address)
}

fn load_program() -> Program {
    // compile_cairo_files(
    //     "contracts.cairo",
    //     2**251 + 17 * 2**192 + 1, // default cairo prime
    //     //main_scope=ScopedName.from_string("starkware.starknet.core.os.contracts"),
    // )
    todo!()
}

/// Returns the serialization of a contract as a list of field elements.
fn get_contract_class_struct(
    identifiers: IdentifierManager, contract_class: ContractClass
) -> Result<CairoStructProxy, _> {
    // kinda magic
    // structs = CairoStructFactory(
    //     identifiers=identifiers,
    //     additional_imports=[
    //         "starkware.starknet.core.os.contracts.ContractClass",
    //         "starkware.starknet.core.os.contracts.ContractEntryPoint",
    //     ],
    // ).structs

    let API_VERSION_IDENT = identifiers.get_by_full_name(
        ScopedName.from_string("starkware.starknet.core.os.contracts.API_VERSION")
    )
    assert isinstance(API_VERSION_IDENT, ConstDefinition)

    let external_functions, l1_handlers, constructors = (
        get_contract_entry_points(
            structs=structs,
            contract_class=contract_class,
            entry_point_type=entry_point_type,
        )
        for entry_point_type in (
            EntryPointType.EXTERNAL,
            EntryPointType.L1_HANDLER,
            EntryPointType.CONSTRUCTOR,
        )
    )
    let flat_external_functions, flat_l1_handlers, flat_constructors = (
        list(itertools.chain.from_iterable(entry_points))
        for entry_points in (external_functions, l1_handlers, constructors)
    )

    let builtin_list = contract_class.program.builtins;
    return Ok(structs.ContractClass(
        API_VERSION_IDENT.value,
        n_external_functions=len(external_functions),
        external_functions=flat_external_functions,
        n_l1_handlers=len(l1_handlers),
        l1_handlers=flat_l1_handlers,
        n_constructors=len(constructors),
        constructors=flat_constructors,
        n_builtins=len(builtin_list),
        builtin_list,
        hinted_class_hash=compute_hinted_class_hash(contract_class=contract_class),
        bytecode_length=len(contract_class.program.data),
        bytecode_ptr=contract_class.program.data,
    )
}

fn compute_class_hash_inner(
    contract_class: &ContractClass
) -> BigInt{
    let program = load_program();
    let contract_class_struct = get_contract_class_struct(
        program.identifiers, contract_class
    );
    
    let runner = CairoFunctionRunner(program);
    // we are using the default one, since the only difference is the name
    // let hash_builtin = HashBuiltinRunner(
        //     name="custom_hasher", included=True, ratio=32, hash_func=hash_func
    // )
    // runner.builtin_runners["hash_builtin"] = hash_builtin
    hash_builtin.initialize_segments(runner);

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
