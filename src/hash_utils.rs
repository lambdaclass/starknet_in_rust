use std::vec;

use felt::{felt_str, Felt};
use num_integer::Integer;
use num_traits::Pow;
use starknet_crypto::{pedersen_hash, FieldElement};

use crate::{core::errors::syscall_handler_errors::SyscallHandlerError, utils::Address};

pub fn calculate_contract_address(
    salt: &Address,
    class_hash: &Felt,
    constructor_calldata: &[Felt],
    deployer_address: Address,
) -> Result<Felt, SyscallHandlerError> {
    // Define constants
    let l2_address_upper_bound = Felt::new(2).pow(251) - Felt::new(256);
    let contract_address_prefix = Felt::from_bytes_be("STARKNET_CONTRACT_ADDRESS".as_bytes());

    let constructor_calldata_hash = compute_hash_on_elements(constructor_calldata)?;
    let raw_address_vec = vec![
        contract_address_prefix,
        deployer_address.0,
        salt.0.to_owned(),
        class_hash.to_owned(),
        constructor_calldata_hash,
    ];
    let raw_address = compute_hash_on_elements(&raw_address_vec)?;

    Ok(raw_address.mod_floor(&l2_address_upper_bound))
}

pub(crate) fn compute_hash_on_elements(vec: &[Felt]) -> Result<Felt, SyscallHandlerError> {
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

    let result = Felt::from_bytes_be(&felt_result.to_bytes_be());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use felt::felt_str;

    use super::*;

    #[test]
    fn test_compute_hash_on_elements() {
        let v1 = vec![1.into()];
        let result1 = compute_hash_on_elements(&v1);

        assert_eq!(
            result1,
            Ok(felt_str!(
                "3416122613774376552656914666405609308365843021349846777564025639164215424932"
            ))
        );

        let v2: Vec<Felt> = vec![1.into(), 2.into(), 3.into(), 4.into()];
        let result2 = compute_hash_on_elements(&v2);

        assert_eq!(
            result2,
            Ok(felt_str!(
                "2904394281987469213428308031512088126582033652660815761074595741628288213124"
            ))
        );

        let v3 = vec![
            0.into(),
            15.into(),
            1232.into(),
            felt_str!("8918274123"),
            46534.into(),
        ];
        let result3 = compute_hash_on_elements(&v3);

        assert_eq!(
            result3,
            Ok(felt_str!(
                "183592112522859067029852736072730560878910822643949684307130835577741550985"
            ))
        );
    }

    #[test]
    fn test_calculate_contract_address_from_hash() {
        let result_1 = calculate_contract_address(
            &Address(1.into()),
            &2.into(),
            &[3.into(), 4.into()],
            Address(5.into()),
        );

        assert_eq!(
            result_1,
            Ok(felt_str!(
                "1885555033409779003200115284723341705041371741573881252130189632266543809788"
            ))
        );

        let result_2 = calculate_contract_address(
            &Address(756.into()),
            &543.into(),
            &[124543.into(), 5345345.into(), 89.into()],
            Address(87123.into()),
        );

        assert_eq!(
            result_2,
            Ok(felt_str!(
                "2864535578326518086698404810362457605993575745991923092043914398137702365865"
            ))
        );
    }
}
