use thiserror::Error;

use crate::{
    business_logic::execution::execution_errors::ExecutionError,
    core::errors::contract_address_errors::ContractAddressError,
    definitions::{
        errors::general_config_error::StarknetChainIdError, general_config::StarknetChainId,
    },
    utils_errors::UtilsError,
};

#[derive(Debug, Error)]
pub(crate) enum TransactionError {
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
}
