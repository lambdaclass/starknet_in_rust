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
}
