use std::error;

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
    #[error("Unexpected holes in the event order")]
    UnexpectedHolesInEventOrder,
    #[error("Unexpected holes in the L2-to-L1 message order.")]
    UnexpectedHolesL2toL1Messages,
    #[error("Trace is not enabled for this run")]
    TraceError,
    #[error("Call type {0} not implemented")]
    CallTypeNotImplemented(String),
    #[error("Attemp to return class hash with incorrect call type")]
    CallTypeIsNotDelegate,
    #[error("Attemp to return code address when is None")]
    AttempToUseNoneCodeAddress,
    #[error("error recovering class hash from storage")]
    FailToReadClassHash,
    #[error("error while fetching redata {0}")]
    RetdataError(String),
}
