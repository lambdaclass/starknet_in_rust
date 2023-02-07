use thiserror::Error;

use crate::{
    business_logic::{
        execution::execution_errors::ExecutionError, transaction::error::TransactionError,
    },
    core::errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError},
    definitions::{
        errors::general_config_error::StarknetChainIdError, general_config::StarknetChainId,
    },
};

#[derive(Debug, Error)]
pub(crate) enum StarknetStateError {
    #[error("Invalid message hash key passed to l2 messages")]
    InvalidMessageHash,
    #[error(transparent)]
    ChaindIdException(#[from] StarknetChainIdError),
    #[error(transparent)]
    SyscallException(#[from] SyscallHandlerError),
    #[error(transparent)]
    StateException(#[from] StateError),
    #[error(transparent)]
    ExecuteException(#[from] ExecutionError),
    #[error(transparent)]
    TransactionException(#[from] TransactionError),
}
