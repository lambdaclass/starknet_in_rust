use num_bigint::BigInt;
use thiserror::Error;

use crate::state::state_chache::StorageEntry;

#[derive(Debug, PartialEq, Error)]
pub enum StateError {
    #[error("Missing ContractClassCache")]
    MissingContractClassCache,
    #[error("ContractClassCache must be None")]
    AssignedContractClassCache,
    #[error("Cache already initialized")]
    StateCacheAlreadyInitialized,
    #[error("No class hash assigned for contact address: {0}")]
    NoneClassHash(BigInt),
    #[error("No nonce assigned for contact address: {0}")]
    NoneNonce(BigInt),
    #[error("No storage value assigned for entry: {0:?}")]
    NoneStorage(StorageEntry),
    #[error("Cannot deploy contract at address: {0}")]
    ContractAddressOutOfRangeAddress(BigInt),
    #[error("Requested contract address {0} is unavailable for deployment")]
    ContractAddressUnavailable(BigInt),
}
