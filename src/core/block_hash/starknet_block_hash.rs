use crate::{
    hash_utils::compute_hash_on_elements, syscalls::syscall_handler_errors::SyscallHandlerError,
};
use crate::core::errors::hash_errors::HashError;
use cairo_vm::felt::Felt252;
use starknet_crypto::{pedersen_hash, FieldElement};
use std::iter::zip;

/// Hashes the signatures with the given transaction hashes, to get hashes that take into account the
/// entire transactions, as the original hashes do not include the signatures.

pub fn calculate_tx_hashes_with_signatures(
    tx_hashes: Vec<Felt252>,
    tx_signatures: Vec<Vec<Felt252>>,
) -> Result<Vec<Felt252>, HashError> {
    zip(tx_hashes, tx_signatures)
        .map(|(hash, signature)| calculate_single_tx_hash_with_signature(hash, signature))
        .collect::<Result<Vec<Felt252>, _>>()
}

/// Hashes the signature with the given transaction hash, to get a hash that takes into account the
/// entire transaction, as the original hash does not include the signature.

pub fn calculate_single_tx_hash_with_signature(
    tx_hash: Felt252,
    tx_signature: Vec<Felt252>,
) -> Result<Felt252, > {
    let signature_hash = compute_hash_on_elements(&tx_signature)?;
    let signature_str = signature_hash.to_str_radix(10);
    let tx_hash_str = tx_hash.to_str_radix(10);
    let hash = FieldElement::from_dec_str(&tx_hash_str)
        .map_err(|_| HashError::FailToComputeHash)?;
    let signature = FieldElement::from_dec_str(&signature_str)
        .map_err(|_| HashError::FailToComputeHash)?;
    let new_hash = pedersen_hash(&hash, &signature);
    Ok(Felt252::from_bytes_be(&new_hash.to_bytes_be()))
}

/// Calculates and returns the hash of an event, given its separate fields.
/// I.e., H(from_address, H(keys), H(data)), where each hash chain computation begins
/// with 0 as initialization and ends with its length appended.
pub fn calculate_event_hash(
    from_address: Felt252,
    keys: Vec<Felt252>,
    data: Vec<Felt252>,
) -> Result<Felt252, HashError> {
    let key_hash = compute_hash_on_elements(&keys)?;
    let data_hash = compute_hash_on_elements(&data)?;
    compute_hash_on_elements(&[from_address, key_hash, data_hash])
}

#[cfg(test)]
mod tests {
    use super::*;
    use coverage_helper::test;

    #[test]
    fn calculate_event_hash_test() {
        let from_address = 1.into();
        let keys = vec![300.into(), 301.into()];
        let data = vec![302.into(), 303.into()];

        assert!(calculate_event_hash(from_address, keys, data).is_ok());
    }

    #[test]
    fn calculate_single_tx_hash_test() {
        let tx_hash = 21325412.into();
        let signatures = vec![300.into(), 301.into()];

        assert!(calculate_single_tx_hash_with_signature(tx_hash, signatures).is_ok());
    }

    #[test]
    fn calculate_tx_hashes_with_signatures_test() {
        let tx_hash = vec![21325412.into(), 21322.into(), 212.into()];
        let signatures = vec![
            vec![300.into(), 301.into()],
            vec![30.into(), 32.into()],
            vec![500.into(), 400.into()],
        ];

        assert!(calculate_tx_hashes_with_signatures(tx_hash, signatures).is_ok());
    }
}
