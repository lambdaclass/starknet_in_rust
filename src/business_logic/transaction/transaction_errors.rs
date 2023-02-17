use felt::Felt;
use thiserror::Error;

use crate::core::errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError};

#[derive(Debug, PartialEq, Error)]
pub enum TransactionError {
    #[error("could not convert felt to u64")]
    InvalidFeltConversion,
    #[error("{0}")]
    InvalidNonce(String),
    #[error("The entry_point_selector must be 617075754465154585683856897856256838130216341506379215893724690153393808813, found {0:?}")]
    UnauthorizedEntryPointForInvoke(Felt),
    #[error("Calling other contracts during validate execution is forbidden")]
    UnauthorizedActionOnValidate,
    #[error("Error ExecutionEntryPoint")]
    ExecutionEntryPointError,
    #[error(transparent)]
    SyscallError(#[from] SyscallHandlerError),
    #[error(transparent)]
    StateError(#[from] StateError),
}
