use crate::{
    services::api::contract_class_errors::ContractClassError,
    state::state_cache::StorageEntry,
    storage::errors::storage_errors::StorageError,
    utils::{Address, ClassHash},
};
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum StateError {
    #[error("Missing ContractClassCache")]
    MissingContractClassCache,
    #[error("ContractClassCache must be None")]
    AssignedContractClassCache,
    #[error("Missing key in StorageUpdate Map")]
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
    NoneStoragLeaf(ClassHash),
    #[error("Cannot deploy contract at address: {0:?}")]
    ContractAddressOutOfRangeAddress(Address),
    #[error("Requested contract address {} is unavailable for deployment", (.0).0)]
    ContractAddressUnavailable(Address),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    ContractClass(#[from] ContractClassError),
    #[error("Missing CasmClassCache")]
    MissingCasmClassCache,
    #[error("Constructor calldata is empty")]
    ConstructorCalldataEmpty(),
    #[error("Error in ExecutionEntryPoint")]
    ExecutionEntryPoint(),
    #[error("No compiled class found for compiled_class_hash {0:?}")]
    NoneCompiledClass(ClassHash),
    #[error("No compiled class hash found for class_hash {0:?}")]
    NoneCompiledHash(ClassHash),
    #[error("Missing casm class for hash {0:?}")]
    MissingCasmClass(ClassHash),
    #[error("No class hash declared in class_hash_to_contract_class")]
    MissingClassHash(),
    #[error("Uninitializes class_hash")]
    UninitiaizedClassHash,
}
