use felt::Felt;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum ContractAddressError {
    #[error("Failed with error: {0}")]
    Program(String),
    #[error("Missing identifier: {0}")]
    MissingIdentifier(String),
    #[error("None existing EntryPointType")]
    NoneExistingEntryPointType,
    #[error("Invalid offset: {0}")]
    InvalidOffset(String),
    #[error("Api version can't be None")]
    NoneApiVersion,
    #[error("Memory error: {0}")]
    Memory(String),
    #[error("Index out of range")]
    IndexOutOfRange,
    #[error("Expected integer variant of MaybeRelocatable")]
    ExpectedInteger,
    #[error("Failed to calculate contract address from hash with error: {0}")]
    ContractAddressFromHash(String),
    #[error("CairoRunner error: {0}")]
    CairoRunner(String),
}
