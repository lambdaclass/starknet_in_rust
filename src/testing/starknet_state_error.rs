use thiserror::Error;

use crate::{
    business_logic::execution::execution_errors::ExecutionError,
    core::errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError},
    definitions::{general_config::StarknetChainId, starknet_chain_id_error::StarknetChainIdError},
};

#[derive(Debug, Error)]
pub enum StarknetStateError {
    #[error(transparent)]
    ChaindIdException(#[from] StarknetChainIdError),
    #[error(transparent)]
    SyscallException(#[from] SyscallHandlerError),
    #[error(transparent)]
    StateException(#[from] StateError),
    #[error(transparent)]
    ExecuteException(#[from] ExecutionError),
}
