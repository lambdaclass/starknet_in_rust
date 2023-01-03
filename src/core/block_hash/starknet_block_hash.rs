use std::iter::zip;

use crate::{
    core::{
        errors::syscall_handler_errors::SyscallHandlerError,
        syscalls::syscall_handler::SyscallHandler,
    },
    hash_utils::compute_hash_on_elements,
    utils::{bigint_to_felt, felt_to_bigint},
};
use num_bigint::{BigInt, Sign};
use starknet_crypto::{pedersen_hash, FieldElement};

pub fn calculate_tx_hashes_with_signatures(
    tx_hashes: Vec<BigInt>,
    tx_signatures: Vec<Vec<BigInt>>,
) -> Result<Vec<BigInt>, SyscallHandlerError> {
    let tx_and_signatures = zip(tx_hashes, tx_signatures).collect::<Vec<(BigInt, Vec<BigInt>)>>();
    let mut hashes = Vec::with_capacity(tx_and_signatures.len());

    for (hash, signature) in tx_and_signatures {
        let hash = calculate_single_tx_hash_with_signature(hash, signature)?;
        hashes.push(hash);
    }

    Ok(hashes)
}

// """
// Hashes the signature with the given transaction hash, to get a hash that takes into account the
// entire transaction, as the original hash does not include the signature.
// """

pub fn calculate_single_tx_hash_with_signature(
    tx_hash: BigInt,
    tx_signature: Vec<BigInt>,
) -> Result<BigInt, SyscallHandlerError> {
    let signature_hash = compute_hash_on_elements(&tx_signature)?;
    let hash = bigint_to_felt(&tx_hash)?;
    let signature = bigint_to_felt(&signature_hash)?;
    let new_hash = pedersen_hash(&hash, &signature);
    Ok(felt_to_bigint(Sign::Plus, &new_hash))
}

// Calculates and returns the hash of an event, given its separate fields.
// I.e., H(from_address, H(keys), H(data)), where each hash chain computation begins
// with 0 as initialization and ends with its length appended.
pub fn calculate_event_hash(
    from_address: BigInt,
    keys: Vec<BigInt>,
    data: Vec<BigInt>,
) -> Result<BigInt, SyscallHandlerError> {
    let key_hash = compute_hash_on_elements(&keys)?;
    let data_hash = compute_hash_on_elements(&data)?;
    compute_hash_on_elements(&[from_address, key_hash, data_hash])
}
