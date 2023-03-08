use crate::{
    business_logic::{execution::error::ExecutionError, transaction::error::TransactionError},
    core::errors::{
        contract_address_errors::ContractAddressError, state_errors::StateError,
        syscall_handler_errors::SyscallHandlerError,
    },
    services::api::contract_class::EntryPointType,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error(transparent)]
    OpenFileError(std::io::Error),
    #[error(transparent)]
    ComputeClassHashError(ContractAddressError),
    #[error(transparent)]
    ComputeAddressError(SyscallHandlerError),
    #[error(transparent)]
    ComputeTransactionHashError(SyscallHandlerError),
    #[error("Failed to convert {0} to Felt")]
    ParseFeltError(String),
    #[error("Failed to get entry point for function `{0}`")]
    FunctionEntryPointError(String),
    #[error("Failed to get entry point selector by type`{0:?}`")]
    EntryPointType(EntryPointType),
    #[error("Failed to get entry point at array position `{0}`")]
    EntryPointIndex(usize),
    #[error(transparent)]
    ExecuteFromEntryPointError(ExecutionError),
    #[error(transparent)]
    ServerError(std::io::Error),
    #[error(transparent)]
    StateError(StateError),
    #[error(transparent)]
    TransactionError(TransactionError),
}
