use crate::{syscalls::syscall_handler_errors::SyscallHandlerError, utils::Address};
use cairo_vm::felt::Felt252;
use num_integer::Integer;
use num_traits::Pow;
use starknet_crypto::{pedersen_hash, FieldElement};
use std::vec;

/// Computes the contract address.
///
/// It is calculated using the following formula:
/// ```text
/// contract_address := pedersen(
///    “STARKNET_CONTRACT_ADDRESS”,
///    caller_address,
///    salt,
///    class_hash,
///    pedersen(constructor_calldata))
///```
///
/// # Arguments
///
/// * `salt` - Part of the deploy transaction
/// * `class_hash` - The hash value of the contract class.
/// * `constructor_calldata` - A slice of `Felt252` elements representing the constructor calldata.
/// * `deployer_address` - The address of the deployer/caller of the contract.
///
/// # Returns
///
/// Returns a `Result` containing the computed contract address.
/// If any errors occur during the hash computation or other operations, an `Err` variant containing
/// a `SyscallHandlerError` is returned.
///
/// # Examples
///
/// ```
/// use starknet_in_rust::{hash_utils::calculate_contract_address, utils::Address, Felt252};
///
/// let salt = Felt252::from(123_u16);
/// let class_hash = Felt252::from(456_u16);
/// let constructor_calldata = vec![
///     Felt252::from(10_u16),
///     Felt252::from(20_u16),
///     Felt252::from(30_u16),
/// ];
/// let deployer_address = Address(Felt252::from(789_u16));
///
/// match calculate_contract_address(&salt, &class_hash, &constructor_calldata, deployer_address) {
///     Ok(contract_address) => {
///         println!("Computed contract address: {:?}", contract_address);
///     }
///     Err(err) => {
///         println!("Error occurred: {:?}", err);
///     }
/// }
/// ```
pub fn calculate_contract_address(
    salt: &Felt252,
    class_hash: &Felt252,
    constructor_calldata: &[Felt252],
    deployer_address: Address,
) -> Result<Felt252, SyscallHandlerError> {
    // Define constants
    let l2_address_upper_bound = Felt252::new(2).pow(251) - Felt252::new(256);
    let contract_address_prefix = Felt252::from_bytes_be("STARKNET_CONTRACT_ADDRESS".as_bytes());

    let constructor_calldata_hash = compute_hash_on_elements(constructor_calldata)?;
    let raw_address_vec = vec![
        contract_address_prefix,
        deployer_address.0,
        salt.to_owned(),
        class_hash.to_owned(),
        constructor_calldata_hash,
    ];
    let raw_address = compute_hash_on_elements(&raw_address_vec)?;

    Ok(raw_address.mod_floor(&l2_address_upper_bound))
}

/// Computes Pedersen hash for a slice of `Felt252` elements.
///
/// # Arguments
///
/// * `vec` - A slice of `Felt252` elements representing the input vector.
///
/// # Returns
///
/// Returns a `Result` containing the computed Pedersen hash value as `Felt252`.
/// If any errors occur during the conversion or hash computation, an `Err` variant containing a `SyscallHandlerError`
/// is returned.
///
/// # Examples
///
/// ```
/// use starknet_in_rust::Felt252;
/// use starknet_in_rust::hash_utils::compute_hash_on_elements;
///
/// let input_vec = vec![
///     Felt252::from(10_u16),
///     Felt252::from(20_u16),
///     Felt252::from(30_u16),
/// ];
///
/// match compute_hash_on_elements(&input_vec) {
///     Ok(hash_value) => {
///         println!("Computed hash value: {:?}", hash_value);
///     }
///     Err(err) => {
///         println!("Error occurred: {:?}", err);
///     }
/// }
/// ```
pub fn compute_hash_on_elements(vec: &[Felt252]) -> Result<Felt252, SyscallHandlerError> {
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

    let result = Felt252::from_bytes_be(&felt_result.to_bytes_be());
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_vm::felt::felt_str;
    use coverage_helper::test;

    #[test]
    fn test_compute_hash_on_elements() {
        let v1 = vec![1.into()];
        let result1 = compute_hash_on_elements(&v1);

        assert_matches!(
        result1,
            Ok(x) if x == felt_str!(
                "3416122613774376552656914666405609308365843021349846777564025639164215424932"
            )
        );

        let v2: Vec<Felt252> = vec![1.into(), 2.into(), 3.into(), 4.into()];
        let result2 = compute_hash_on_elements(&v2);

        assert_matches!(
        result2,
            Ok(x) if x == felt_str!(
                "2904394281987469213428308031512088126582033652660815761074595741628288213124"
            )
        );

        let v3 = vec![
            0.into(),
            15.into(),
            1232.into(),
            felt_str!("8918274123"),
            46534.into(),
        ];
        let result3 = compute_hash_on_elements(&v3);

        assert_matches!(
        result3,
            Ok(x) if x == felt_str!(
                "183592112522859067029852736072730560878910822643949684307130835577741550985"
            )
        );
    }

    #[test]
    fn test_calculate_contract_address_from_hash() {
        let result_1 = calculate_contract_address(
            &1.into(),
            &2.into(),
            &[3.into(), 4.into()],
            Address(5.into()),
        );

        assert_matches!(
        result_1,
            Ok(x) if x == felt_str!(
                "1885555033409779003200115284723341705041371741573881252130189632266543809788"
            )
        );

        let result_2 = calculate_contract_address(
            &756.into(),
            &543.into(),
            &[124543.into(), 5345345.into(), 89.into()],
            Address(87123.into()),
        );

        assert_matches!(
            result_2,
            Ok(x) if x == felt_str!(
                "2864535578326518086698404810362457605993575745991923092043914398137702365865"
            )
        );
    }
}
