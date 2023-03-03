use crate::{
    core::errors::{
        contract_address_errors::ContractAddressError, state_errors::StateError,
        syscall_handler_errors::SyscallHandlerError,
    },
    starkware_utils::starkware_errors::StarkwareError,
};
use felt::Felt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransactionError {
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
    #[error("Unimplemented state updates")]
    NotImplemented,
    #[error(transparent)]
    ContractAddressError(#[from] ContractAddressError),
    #[error(transparent)]
    SyscallError(#[from] SyscallHandlerError),
    #[error(transparent)]
    StateError(#[from] StateError),

    #[error("Calling other contracts during validate execution is forbidden")]
    UnauthorizedActionOnValidate,
    #[error("The entry_point_selector must be 617075754465154585683856897856256838130216341506379215893724690153393808813, found {0:?}")]
    UnauthorizedEntryPointForInvoke(Felt),
    #[error("Error ExecutionEntryPoint")]
    ExecutionEntryPointError,
    #[error(transparent)]
    StarkwareException(#[from] StarkwareError),
}
