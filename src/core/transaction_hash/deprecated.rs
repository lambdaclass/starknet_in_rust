use crate::core::errors::hash_errors::HashError;
use crate::transaction::error::TransactionError;
use crate::{
    core::contract_address::compute_deprecated_class_hash,
    definitions::constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR, hash_utils::compute_hash_on_elements,
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    transaction::Address,
};
use cairo_vm::Felt252;
use num_traits::Zero;

use super::TransactionHashPrefix;

// Deprecated transaction hash functions (V0-1-2 txs)

/// Calculates the transaction hash in the StarkNet network - a unique identifier of the
/// transaction, for transactions of version 2 or lower
/// The transaction hash is a hash chain of the following information:
///    1. A prefix that depends on the transaction type.
///    2. The transaction's version.
///    3. Contract address.
///    4. Entry point selector.
///    5. A hash chain of the calldata.
///    6. The transaction's maximum fee.
///    7. The network's chain ID.
/// Each hash chain computation begins with 0 as initialization and ends with its length appended.
/// The length is appended in order to avoid collisions of the following kind:
/// ```txt
///     H([x,y,z]) = h(h(x,y),z) = H([w, z]) where w = h(x,y)
/// ```
#[allow(clippy::too_many_arguments)]
pub fn deprecated_calculate_transaction_hash_common(
    tx_hash_prefix: TransactionHashPrefix,
    version: Felt252,
    contract_address: &Address,
    entry_point_selector: Felt252,
    calldata: &[Felt252],
    max_fee: u128,
    chain_id: Felt252,
    additional_data: &[Felt252],
) -> Result<Felt252, HashError> {
    let calldata_hash = compute_hash_on_elements(calldata)?;

    let mut data_to_hash: Vec<Felt252> = vec![
        tx_hash_prefix.get_prefix(),
        version,
        contract_address.0,
        entry_point_selector,
        calldata_hash,
        max_fee.into(),
        chain_id,
    ];

    data_to_hash.extend(additional_data.iter().cloned());

    compute_hash_on_elements(&data_to_hash)
}

/// Calculate the hash for deploying a transaction.
pub fn deprecated_calculate_deploy_transaction_hash(
    version: Felt252,
    contract_address: &Address,
    constructor_calldata: &[Felt252],
    chain_id: Felt252,
) -> Result<Felt252, HashError> {
    deprecated_calculate_transaction_hash_common(
        TransactionHashPrefix::Deploy,
        version,
        contract_address,
        *CONSTRUCTOR_ENTRY_POINT_SELECTOR,
        constructor_calldata,
        0, // Considered 0 for Deploy transaction hash calculation purposes.
        chain_id,
        &[],
    )
}

/// Calculate the hash for deploying an account transaction.
#[allow(clippy::too_many_arguments)]
pub(super) fn deprecated_calculate_deploy_account_transaction_hash(
    version: Felt252,
    contract_address: &Address,
    class_hash: Felt252,
    constructor_calldata: &[Felt252],
    max_fee: u128,
    nonce: Felt252,
    salt: Felt252,
    chain_id: Felt252,
) -> Result<Felt252, HashError> {
    let mut calldata: Vec<Felt252> = vec![class_hash, salt];
    calldata.extend_from_slice(constructor_calldata);

    deprecated_calculate_transaction_hash_common(
        TransactionHashPrefix::DeployAccount,
        version,
        contract_address,
        Felt252::ZERO,
        &calldata,
        max_fee,
        chain_id,
        &[nonce],
    )
}

/// Calculate the hash for a declared transaction.
pub fn deprecated_calculate_declare_transaction_hash(
    contract_class: &ContractClass,
    chain_id: Felt252,
    sender_address: &Address,
    max_fee: u128,
    version: Felt252,
    nonce: Felt252,
) -> Result<Felt252, HashError> {
    let class_hash = compute_deprecated_class_hash(contract_class)
        .map_err(|e| HashError::FailedToComputeHash(e.to_string()))?;

    let (calldata, additional_data) = if !version.is_zero() {
        (vec![class_hash], vec![nonce])
    } else {
        (Vec::new(), vec![class_hash])
    };

    deprecated_calculate_transaction_hash_common(
        TransactionHashPrefix::Declare,
        version,
        sender_address,
        Felt252::ZERO,
        &calldata,
        max_fee,
        chain_id,
        &additional_data,
    )
}

/// Calculate the hash for an invoke transaction.
pub(super) fn deprecated_calculate_invoke_transaction_hash(
    chain_id: Felt252,
    contract_address: &Address,
    entry_point_selector: Felt252,
    max_fee: u128,
    version: Felt252,
    nonce: Option<Felt252>,
    calldata: &[Felt252],
) -> Result<Felt252, TransactionError> {
    let (entry_point_selector_field, additional_data) =
        preprocess_invoke_function_fields(entry_point_selector, nonce, version)?;
    deprecated_calculate_transaction_hash_common(
        TransactionHashPrefix::Invoke,
        version,
        contract_address,
        entry_point_selector_field,
        calldata,
        max_fee,
        chain_id,
        &additional_data,
    )
    .map_err(TransactionError::HashError)
}

// Performs validation on fields related to function invocation transaction.
// InvokeFunction transaction.
// Deduces and returns fields required for hash calculation of
fn preprocess_invoke_function_fields(
    entry_point_selector: Felt252,
    nonce: Option<Felt252>,
    version: Felt252,
) -> Result<(Felt252, Vec<Felt252>), TransactionError> {
    if version.is_zero() {
        match nonce {
            Some(_) => Err(TransactionError::InvokeFunctionZeroHasNonce),
            None => {
                let additional_data = Vec::new();
                let entry_point_selector_field = entry_point_selector;
                Ok((entry_point_selector_field, additional_data))
            }
        }
    } else {
        match nonce {
            Some(n) => {
                let additional_data = vec![n];
                let entry_point_selector_field = Felt252::ZERO;
                Ok((entry_point_selector_field, additional_data))
            }
            None => Err(TransactionError::InvokeFunctionNonZeroMissingNonce),
        }
    }
}

// ----------------------------
//      V2 Hash Functions
// ----------------------------

pub(super) fn deprecated_calculate_declare_v2_transaction_hash(
    sierra_class_hash: Felt252,
    compiled_class_hash: Felt252,
    chain_id: Felt252,
    sender_address: &Address,
    max_fee: u128,
    version: Felt252,
    nonce: Felt252,
) -> Result<Felt252, HashError> {
    let calldata = [sierra_class_hash].to_vec();
    let additional_data = [nonce, compiled_class_hash].to_vec();

    deprecated_calculate_transaction_hash_common(
        TransactionHashPrefix::Declare,
        version,
        sender_address,
        Felt252::ZERO,
        &calldata,
        max_fee,
        chain_id,
        &additional_data,
    )
}

#[cfg(test)]
mod tests {
    use cairo_vm::Felt252;
    use coverage_helper::test;

    use crate::definitions::block_context::StarknetChainId;

    use super::*;

    #[test]
    fn deprecated_calculate_transaction_hash_common_test() {
        let tx_hash_prefix = TransactionHashPrefix::Declare;
        let version = 0.into();
        let contract_address = Address(42.into());
        let entry_point_selector = 100.into();
        let calldata = vec![540.into(), 338.into()];
        let max_fee = 10;
        let chain_id = 1.into();
        let additional_data: Vec<Felt252> = Vec::new();

        // Expected value taken from Python implementation of deprecated_calculate_transaction_hash_common function
        let expected = Felt252::from_dec_str(
            "2401716064129505935860131145275652294383308751137512921151718435935971973354",
        )
        .unwrap();

        let result = deprecated_calculate_transaction_hash_common(
            tx_hash_prefix,
            version,
            &contract_address,
            entry_point_selector,
            &calldata,
            max_fee,
            chain_id,
            &additional_data,
        )
        .unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn calculate_declare_hash_test() {
        let chain_id = StarknetChainId::MainNet;
        let sender_address = Address(
            Felt252::from_dec_str(
                "78963962122521774108119849325604561253807220406669671815499681746608877924",
            )
            .unwrap(),
        );
        let max_fee = 30580718124600;
        let version = 1.into();
        let nonce = 3746.into();
        let class_hash = Felt252::from_dec_str(
            "1935775813346111469198021973672033051732472907985289186515250543849860001197",
        )
        .unwrap();

        let (calldata, additional_data) = (vec![class_hash], vec![nonce]);

        let tx = deprecated_calculate_transaction_hash_common(
            TransactionHashPrefix::Declare,
            version,
            &sender_address,
            Felt252::ZERO,
            &calldata,
            max_fee,
            chain_id.to_felt(),
            &additional_data,
        )
        .unwrap();

        assert_eq!(
            tx,
            Felt252::from_dec_str(
                "446404108171603570739811156347043235876209711235222547918688109133687877504"
            )
            .unwrap()
        )
    }

    #[test]
    fn preprocess_invoke_function_fields_nonce_is_none() {
        let entry_point_selector =
            Felt252::from_hex("0x112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9")
                .unwrap();
        let result = preprocess_invoke_function_fields(entry_point_selector, None, 0.into());

        let expected_additional_data: Vec<Felt252> = Vec::new();
        let expected_entry_point_selector_field = entry_point_selector;
        assert_eq!(
            result.unwrap(),
            (
                expected_entry_point_selector_field,
                expected_additional_data
            )
        )
    }

    #[test]
    fn preprocess_invoke_function_fields_version_one_with_no_nonce_should_fail() {
        let expected_error = preprocess_invoke_function_fields(
            Felt252::from_hex("0x112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9")
                .unwrap(),
            None,
            1.into(),
        );
        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::InvokeFunctionNonZeroMissingNonce
        )
    }

    #[test]
    fn preprocess_invoke_function_fields_version_one_with_no_nonce_with_query_base_should_fail() {
        let expected_error = preprocess_invoke_function_fields(
            Felt252::from_hex("0x112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9")
                .unwrap(),
            None,
            *crate::definitions::constants::QUERY_VERSION_1,
        );
        assert!(expected_error.is_err());
    }

    #[test]
    fn preprocess_invoke_function_fields_version_zero_with_non_zero_nonce_should_fail() {
        let expected_error = preprocess_invoke_function_fields(
            Felt252::from_hex("0x112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9")
                .unwrap(),
            Some(1.into()),
            0.into(),
        )
        .unwrap_err();
        assert_matches!(expected_error, TransactionError::InvokeFunctionZeroHasNonce)
    }
}
