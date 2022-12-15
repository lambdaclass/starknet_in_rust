use num_bigint::{BigInt, Sign};
use starknet_crypto::{pedersen_hash, FieldElement};

use crate::core::errors::syscall_handler_errors::SyscallHandlerError;

pub fn calculate_contract_address_from_hash(
    salt: &BigInt,
    class_hash: &BigInt,
    constructor_calldata: Vec<BigInt>,
    deployer_address: u64,
) -> Result<BigInt, SyscallHandlerError> {
    // pedersen_hash(x, y)
    todo!()
}

fn compute_hash_on_elements(vec: Vec<BigInt>) -> Result<BigInt, SyscallHandlerError> {
    let mut felt_vec: Vec<FieldElement> = vec
        .into_iter()
        .map(|num| FieldElement::from_dec_str(&num.to_str_radix(10)).unwrap())
        .collect();
    felt_vec.push(FieldElement::from(felt_vec.len()));
    felt_vec.insert(0, FieldElement::from(0_u16));
    let felt_result = felt_vec
        .into_iter()
        .reduce(|x, y| pedersen_hash(&x, &y))
        .unwrap();
    let result = BigInt::from_bytes_be(Sign::Plus, &felt_result.to_bytes_be());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash_on_elements() {
        let v1 = vec![BigInt::from(1)];
        let result1 = compute_hash_on_elements(v1).unwrap();
        let v2 = vec![
            BigInt::from(1),
            BigInt::from(2),
            BigInt::from(3),
            BigInt::from(4),
        ];
        let result2 = compute_hash_on_elements(v2).unwrap();

        assert_eq!(
            result1,
            BigInt::parse_bytes(
                b"3416122613774376552656914666405609308365843021349846777564025639164215424932",
                10
            )
            .unwrap()
        );
        assert_eq!(
            result2,
            BigInt::parse_bytes(
                b"2904394281987469213428308031512088126582033652660815761074595741628288213124",
                10
            )
            .unwrap()
        );
    }
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
