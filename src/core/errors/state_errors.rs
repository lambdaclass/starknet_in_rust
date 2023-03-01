use crate::{
    business_logic::state::state_cache::StorageEntry,
    services::api::contract_class_errors::ContractClassError,
    starknet_storage::errors::storage_errors::StorageError, utils::Address,
};
use felt::Felt;
use thiserror::Error;

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
    NoneContractState(Address),
    #[error("No class hash assigned for contact address: {0:?}")]
    NoneClassHash(Address),
    #[error("No nonce assigned for contact address: {0:?}")]
    NoneNonce(Address),
    #[error("No storage value assigned for entry: {0:?}")]
    NoneStorage(StorageEntry),
    #[error("No storage leaf assigned for key: {0:?}")]
    NoneStoragLeaf([u8; 32]),
    #[error("Cannot deploy contract at address: {0:?}")]
    ContractAddressOutOfRangeAddress(Address),
    #[error("Requested contract address {0:?} is unavailable for deployment")]
    ContractAddressUnavailable(Address),
    #[error("error converting {0} to u64")]
    ConversionError(Felt),
    #[error(transparent)]
    StorageError(#[from] StorageError),
    #[error(transparent)]
    ContractClassError(#[from] ContractClassError),
    #[error("constructor entry points must be empty")]
    ConstructorEntryPointsError(),
    #[error("Error in ExecutionEntryPoint")]
    ExecutionEntryPointError(),
}
