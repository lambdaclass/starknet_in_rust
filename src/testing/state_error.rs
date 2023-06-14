use thiserror::Error;

use crate::{
    core::errors::state_errors::StateError, syscalls::syscall_handler_errors::SyscallHandlerError,
    transaction::error::TransactionError,
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
