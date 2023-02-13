use thiserror::Error;

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
    #[error("Unexpected holes in the event order")]
    UnexpectedHolesInEventOrder,
    #[error("Unexpected holes in the L2-to-L1 message order.")]
    UnexpectedHolesL2toL1Messages,
}
