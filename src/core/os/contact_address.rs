use num_bigint::BigInt;

use crate::core::errors::syscall_handler_errors::SyscallHandlerError;

pub fn calculate_contract_address_from_hash(
    salt: &BigInt,
    class_hash: &BigInt,
    constructor_calldata: Vec<&BigInt>,
    deployer_address: &BigInt,
) -> Result<BigInt, SyscallHandlerError> {
    todo!()
}

/*
def calculate_contract_address_from_hash(
    salt: int,
    class_hash: int,
    constructor_calldata: Sequence[int],
    deployer_address: int,
    hash_function: Callable[[int, int], int] = pedersen_hash,
) -> int:
    """
    Same as calculate_contract_address(), except that it gets class_hash instead of
    contract_class.
    """
    constructor_calldata_hash = compute_hash_on_elements(
        data=constructor_calldata, hash_func=hash_function
    )
    raw_address = compute_hash_on_elements(
        data=[
            CONTRACT_ADDRESS_PREFIX,
            deployer_address,
            salt,
            class_hash,
            constructor_calldata_hash,
        ],
        hash_func=hash_function,
    )

    return raw_address % L2_ADDRESS_UPPER_BOUND

*/
