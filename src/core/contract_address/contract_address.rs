use num_bigint::BigInt;

use crate::{services::api::contract_class::ContractClass, core::errors::syscall_handler_errors::SyscallHandlerError, hash_utils::calculate_contract_address_from_hash};

pub(crate) fn calculate_contract_address(
    salt: &BigInt,
    contract_class: &ContractClass,
    constructor_calldata: &[BigInt],
    deployer_address: u64,
) -> Result<BigInt, SyscallHandlerError> { // TODO: maybe this is not the right error type. 
    let class_hash = compute_class_hash(contract_class);

    calculate_contract_address_from_hash(
        salt,
        class_hash,
        constructor_calldata,
        deployer_address,
    )
}


pub(crate) fn compute_class_hash(
    contract_class: &ContractClass
) -> Result<BigInt, SyscallHandlerError> { // TODO: maybe this is not the right error type. 
    let cache = class_hash_cache_ctx_var.get()
    if cache is None:
        return compute_class_hash_inner(contract_class=contract_class, hash_func=hash_func)

    contract_class_bytes = contract_class.dumps(sort_keys=True).encode()
    key = (starknet_keccak(data=contract_class_bytes), hash_func)

    if key not in cache:
        cache[key] = compute_class_hash_inner(contract_class=contract_class, hash_func=hash_func)
    
    cache[key]
}
