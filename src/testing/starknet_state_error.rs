use thiserror::Error;

use crate::{
    business_logic::transaction::error::TransactionError,
    core::errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError},
};

#[derive(Debug, Error)]
pub enum StarknetStateError {
    #[error("Invalid message hash key passed to l2 messages")]
    InvalidMessageHash,
    #[error(transparent)]
    Syscall(#[from] SyscallHandlerError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
}
