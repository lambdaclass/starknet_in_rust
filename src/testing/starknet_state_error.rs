use thiserror::Error;

use crate::{
    business_logic::execution::execution_errors::ExecutionError,
    core::errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError},
    definitions::general_config::StarknetChainId,
};

#[derive(Debug, Error)]
pub enum StarknetStateError {
    #[error(transparent)]
    SyscallException(#[from] SyscallHandlerError),
    #[error(transparent)]
    StateException(#[from] StateError),
    #[error(transparent)]
    ExecuteException(#[from] ExecutionError),
}
