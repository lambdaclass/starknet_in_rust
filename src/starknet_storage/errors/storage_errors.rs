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

#[test]
fn test_from_serde_json_error_for_storage_error() {
    let bugged_json: Result<starknet_api::state::ContractClass, serde_json::Error> =
        serde_json::from_str("{");
    let json_error = bugged_json.unwrap_err();
    let storage_error = StorageError::from(json_error);

    assert_eq!(
        storage_error,
        StorageError::SerdeError(String::from(
            "EOF while parsing an object at line 1 column 1"
        ))
    );
}
