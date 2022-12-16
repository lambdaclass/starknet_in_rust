use std::vec;

use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use starknet_crypto::{pedersen_hash, FieldElement};

use crate::{bigint, core::errors::syscall_handler_errors::SyscallHandlerError};

pub fn calculate_contract_address_from_hash(
    salt: &BigInt,
    class_hash: &BigInt,
    constructor_calldata: &[BigInt],
    deployer_address: u64,
) -> Result<BigInt, SyscallHandlerError> {
    // Define constants
    let l2_address_upper_bound = bigint!(2).pow(251) - 256;
    let contract_address_prefix =
        BigInt::from_bytes_be(Sign::Plus, "STARKNET_CONTRACT_ADDRESS".as_bytes());

    let constructor_calldata_hash = compute_hash_on_elements(constructor_calldata)?;
    let raw_address_vec = vec![
        contract_address_prefix,
        bigint!(deployer_address),
        salt.to_owned(),
        class_hash.to_owned(),
        constructor_calldata_hash,
    ];
    let raw_address = compute_hash_on_elements(&raw_address_vec)?;

    Ok(raw_address.mod_floor(&l2_address_upper_bound))
}

fn compute_hash_on_elements(vec: &[BigInt]) -> Result<BigInt, SyscallHandlerError> {
    let mut felt_vec = vec
        .iter()
        .map(|num| {
            FieldElement::from_dec_str(&num.to_str_radix(10))
                .map_err(|_| SyscallHandlerError::FailToComputeHash)
        })
        .collect::<Result<Vec<FieldElement>, SyscallHandlerError>>()?;
    felt_vec.push(FieldElement::from(felt_vec.len()));
    felt_vec.insert(0, FieldElement::from(0_u16));
    let felt_result = felt_vec
        .into_iter()
        .reduce(|x, y| pedersen_hash(&x, &y))
        .ok_or(SyscallHandlerError::FailToComputeHash)?;
    let result = BigInt::from_bytes_be(Sign::Plus, &felt_result.to_bytes_be());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_rs::bigint_str;

    #[test]
    fn test_compute_hash_on_elements() {
        let v1 = vec![bigint!(1)];
        let result1 = compute_hash_on_elements(&v1);
        let v2 = vec![bigint!(1), bigint!(2), bigint!(3), bigint!(4)];
        let result2 = compute_hash_on_elements(&v2);

        assert_eq!(
            result1,
            Ok(bigint_str!(
                b"3416122613774376552656914666405609308365843021349846777564025639164215424932"
            ))
        );
        assert_eq!(
            result2,
            Ok(bigint_str!(
                b"2904394281987469213428308031512088126582033652660815761074595741628288213124"
            ))
        );
    }
}
