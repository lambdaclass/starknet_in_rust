use crate::{
    services::api::contract_class_errors::ContractClassError,
    state::state_cache::StorageEntry,
    utils::{Address, ClassHash},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("Missing key in StorageUpdate Map")]
    EmptyKeyInStorage,
    #[error("Try to create a CarriedState from a None parent")]
    ParentCarriedStateIsNone,
    #[error("Cache already initialized")]
    StateCacheAlreadyInitialized,
    #[error("No contract state assigned for contract address: {0:?}")]
    NoneContractState(Address),
    #[error("No class hash assigned for contract address: {0:?}")]
    NoneClassHash(Address),
    #[error("No nonce assigned for contract address: {0:?}")]
    NoneNonce(Address),
    #[error("No storage value assigned for entry: {0:?}")]
    NoneStorage(StorageEntry),
    #[error("No storage leaf assigned for key: {0:?}")]
    NoneStoragLeaf(ClassHash),
    #[error("Cannot deploy contract at address: {0:?}")]
    ContractAddressOutOfRangeAddress(Address),
    #[error("Requested contract address {} is unavailable for deployment", (.0).0)]
    ContractAddressUnavailable(Address),
    #[error(transparent)]
    ContractClass(#[from] ContractClassError),
    #[error("Constructor calldata is empty")]
    ConstructorCalldataEmpty,
    #[error("Error in ExecutionEntryPoint")]
    ExecutionEntryPoint,
    #[error("No compiled class found for compiled_class_hash {0:?}")]
    NoneCompiledClass(ClassHash),
    #[error("No compiled class hash found for class_hash {0:?}")]
    NoneCompiledHash(ClassHash),
    #[error("Missing casm class for hash {0:?}")]
    MissingCasmClass(ClassHash),
    #[error("Uninitializes class_hash")]
    UninitiaizedClassHash,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0:?}")]
    CustomError(String),
}
