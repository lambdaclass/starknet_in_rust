use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum StorageError {
    #[error("Data not available")]
    ErrorFetchingData,
}
