use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum StorageError {
    #[error("Data not available")]
    ErrorFetchingData,
    #[error("Slice with incorrect length")]
    IncorrectDataSize,
    #[error("Incorrect utf8 enconding")]
    IncorrectUtf8Enconding,
    #[error("Attempt to remove missing key")]
    RemoveMissingKey,
}
