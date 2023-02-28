use thiserror::Error;

use crate::{
    business_logic::execution::execution_errors::ExecutionError,
    core::errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError},
};

#[derive(Debug, Error)]
pub enum StarknetStateError {
    #[error("Invalid message hash key passed to l2 messages")]
    InvalidMessageHash,
    #[error(transparent)]
    SyscallException(#[from] SyscallHandlerError),
    #[error(transparent)]
    StateException(#[from] StateError),
    #[error(transparent)]
    ExecuteException(#[from] ExecutionError),
}
