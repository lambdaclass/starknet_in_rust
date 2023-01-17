use thiserror::Error;

use crate::core::errors;
#[derive(Debug, PartialEq, Eq, Error)]
pub enum ExecutionError {
    #[error("Missing field for TxStruct")]
    MissingTxStructField,
    #[error("Expected an int value but get wrong data type")]
    NotAFeltValue,
    #[error("Expected a relocatable value but get wrong data type")]
    NotARelocatableValue,
    #[error("Error converting from {0} to {1}")]
    ErrorInDataConversion(String, String),
}
