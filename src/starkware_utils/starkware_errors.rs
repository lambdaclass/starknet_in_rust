use crate::core::errors::state_errors::StateError;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum StarkwareError {
    #[error("Cannot pass calldata to a contract with no constructor.")]
    TransactionFailed,
    #[error("Unexpected holes in the L2-to-L1 message order.")]
    UnexpectedHolesL2toL1Messages,
    #[error("Invalid Block number.")]
    InvalidBlockNumber,
    #[error("Invalid Block Timestamp.")]
    InvalidBlockTimestamp,
    #[error(transparent)]
    StateError(#[from] StateError),
}
