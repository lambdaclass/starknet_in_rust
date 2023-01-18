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
    #[error("Serde error: {0}")]
    SerdeError(String),
}

impl From<serde_json::Error> for StorageError {
    fn from(error: serde_json::Error) -> Self {
        StorageError::SerdeError(error.to_string())
    }
}
