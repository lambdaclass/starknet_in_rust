use felt::Felt;
use thiserror::Error;

use crate::{
    business_logic::{fact_state::contract_state::ContractState, state::state_cache::StorageEntry},
    starknet_storage::errors::storage_errors::StorageError,
};

#[derive(Debug, PartialEq, Error)]
pub enum StateError {
    #[error("Missing ContractClassCache")]
    MissingContractClassCache,
    #[error("ContractClassCache must be None")]
    AssignedContractClassCache,
    #[error("Missing key that in StorageUpdate Map")]
    EmptyKeyInStorage,
    #[error("Try to create a CarriedState from a None parent")]
    ParentCarriedStateIsNone,
    #[error("Cache already initialized")]
    StateCacheAlreadyInitialized,
    #[error("No contract state assigned for contact address: {0:?}")]
    NoneContractState(Felt),
    #[error("No class hash assigned for contact address: {0}")]
    NoneClassHash(Felt),
    #[error("No nonce assigned for contact address: {0}")]
    NoneNonce(Felt),
    #[error("No storage value assigned for entry: {0:?}")]
    NoneStorage(StorageEntry),
    #[error("Cannot deploy contract at address: {0}")]
    ContractAddressOutOfRangeAddress(Felt),
    #[error("Requested contract address {0} is unavailable for deployment")]
    ContractAddressUnavailable(Felt),
    #[error(transparent)]
    StorageError(#[from] StorageError),
}
