use crate::{
    core::{
        errors::syscall_handler_errors::SyscallHandlerError,
        syscalls::syscall_handler::SyscallHandler,
    },
    hash_utils::compute_hash_on_elements,
};
use felt::{Felt, FeltOps};
use num_bigint::{BigInt, Sign};
use starknet_crypto::{pedersen_hash, FieldElement};
use std::iter::zip;

// --------------------------------------------------------------
// TODO:
//  * calculate_block_hash
//  * calculate_patricia_root
//  there are missing structures to implement this functions yet
// -------------------------------------------------------------

pub fn calculate_tx_hashes_with_signatures(
    tx_hashes: Vec<Felt>,
    tx_signatures: Vec<Vec<Felt>>,
) -> Result<Vec<Felt>, SyscallHandlerError> {
    let tx_and_signatures = zip(tx_hashes, tx_signatures).collect::<Vec<(Felt, Vec<Felt>)>>();
    let mut hashes = Vec::with_capacity(tx_and_signatures.len());

    for (hash, signature) in tx_and_signatures {
        let hash = calculate_single_tx_hash_with_signature(hash, signature)?;
        hashes.push(hash);
    }

    Ok(hashes)
}

///
/// Hashes the signature with the given transaction hash, to get a hash that takes into account the
/// entire transaction, as the original hash does not include the signature.
///

pub fn calculate_single_tx_hash_with_signature(
    tx_hash: Felt,
    tx_signature: Vec<Felt>,
) -> Result<Felt, SyscallHandlerError> {
    let signature_hash = compute_hash_on_elements(&tx_signature)?;
    let signature_str = signature_hash.to_str_radix(10);
    let tx_hash_str = tx_hash.to_str_radix(10);
    let hash = FieldElement::from_dec_str(&tx_hash_str)
        .map_err(|_| SyscallHandlerError::FailToComputeHash)?;
    let signature = FieldElement::from_dec_str(&signature_str)
        .map_err(|_| SyscallHandlerError::FailToComputeHash)?;
    let new_hash = pedersen_hash(&hash, &signature);
    Ok(Felt::from_bytes_be(&new_hash.to_bytes_be()))
}

/// Calculates and returns the hash of an event, given its separate fields.
/// I.e., H(from_address, H(keys), H(data)), where each hash chain computation begins
/// with 0 as initialization and ends with its length appended.
pub fn calculate_event_hash(
    from_address: Felt,
    keys: Vec<Felt>,
    data: Vec<Felt>,
) -> Result<Felt, SyscallHandlerError> {
    let key_hash = compute_hash_on_elements(&keys)?;
    let data_hash = compute_hash_on_elements(&data)?;
    compute_hash_on_elements(&[from_address, key_hash, data_hash])
}

#[cfg(test)]
mod tests {
    use crate::{starknet_storage::dict_storage::DictStorage, utils::test_utils::storage_key};

    use super::*;

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
