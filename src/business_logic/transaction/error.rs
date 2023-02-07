use thiserror::Error;

use crate::{
    business_logic::execution::execution_errors::ExecutionError,
    core::errors::{
        contract_address_errors::ContractAddressError, state_errors::StateError,
        syscall_handler_errors::SyscallHandlerError,
    },
    definitions::{
        errors::general_config_error::StarknetChainIdError, general_config::StarknetChainId,
    },
    utils_errors::UtilsError,
};

#[derive(Debug, Error)]
pub(crate) enum TransactionError {
    #[error("could not convert felt to u64")]
    InvalidFeltConversion,
    #[error("{0}")]
    InvalidNonce(String),
    #[error(transparent)]
    UtilsError(#[from] UtilsError),
    #[error(transparent)]
    ContractAddressError(#[from] ContractAddressError),
    #[error(transparent)]
    StarknetChaindIdError(#[from] StarknetChainIdError),
    #[error(transparent)]
    ExecutionError(#[from] ExecutionError),
    #[error(transparent)]
    SyscallError(#[from] SyscallHandlerError),
    #[error(transparent)]
    StateError(#[from] StateError),
}
