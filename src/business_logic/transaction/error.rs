use thiserror::Error;

use crate::{
    core::errors::{
        contract_address_errors::ContractAddressError, state_errors::StateError,
        syscall_handler_errors::SyscallHandlerError,
    },
    starkware_utils::starkware_errors::StarkwareError,
    utils_errors::UtilsError,
};

#[derive(Debug, Error)]
pub enum TransactionError {
    #[allow(dead_code)] // TODO: delete this once used
    #[error("Invalid felt convertion to u64")]
    InvalidFeltConversion,
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
    #[error("Could not calculate resources")]
    ResourcesCalculationError,
    #[error("{0}")]
    RunValidationError(String),
    #[error("Missing contract class storage")]
    MissingClassStorage,
    #[error(transparent)]
    UtilsError(#[from] UtilsError),
    #[error(transparent)]
    ContractAddressError(#[from] ContractAddressError),
    #[error(transparent)]
    SyscallError(#[from] SyscallHandlerError),
    #[error(transparent)]
    StateError(#[from] StateError),
    #[error("Calling other contracts during validate execution is forbidden")]
    UnauthorizedActionOnValidate,
    #[error(transparent)]
    StarkwareException(#[from] StarkwareError),
}
