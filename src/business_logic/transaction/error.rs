use crate::core::errors::{
    contract_address_errors::ContractAddressError, state_errors::StateError,
    syscall_handler_errors::SyscallHandlerError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransactionError {
    #[allow(dead_code)] // TODO: delete this once used
    #[error("{0}")]
    InvalidNonce(String),
    #[error("Invalid transaction nonce. Expected: {0} got {1}")]
    InvalidTransactionNonce(String, String),
    #[error("{0}")]
    StarknetError(String),
    #[error("{0}")]
    FeeError(String),
    #[error("Cairo resource names must be contained in fee weights dict")]
    ResourcesError,
    #[error(transparent)]
    ContractAddressError(#[from] ContractAddressError),
    #[error(transparent)]
    SyscallError(#[from] SyscallHandlerError),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error("Calling other contracts during validate execution is forbidden")]
    UnauthorizedActionOnValidate,
}
