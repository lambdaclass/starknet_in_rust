use thiserror::Error;
#[derive(Debug, PartialEq, Error)]

pub enum StarkwareError {
    #[error("Cannot pass calldata to a contract with no constructor.")]
    TransactionFailed,
    #[error("Incorrect data size when converting contract hash.")]
    IncorrectClassHashSize,
    #[error("Unexpected holes in the L2-to-L1 message order.")]
    UnexpectedHolesL2toL1Messages,
    #[error("Invalid Block number.")]
    InvalidBlockNumber,
    #[error("Invalid Block Timestamp.")]
    InvalidBlockTimestamp,
}
