use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;
use crate::{
    core::errors::{
        contract_address_errors::ContractAddressError, hash_errors::HashError,
        state_errors::StateError,
    },
    syscalls::syscall_handler_errors::SyscallHandlerError,
    transaction::error::TransactionError,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ContractAddress(#[from] ContractAddressError),
    #[error(transparent)]
    Syscall(#[from] SyscallHandlerError),
    #[error(transparent)]
    Hashes(#[from] HashError),
    #[error("Failed to convert {0} to Felt")]
    ParseFelt(String),
    #[error("Failed to get entry point for function `{0}`")]
    FunctionEntryPoint(String),
    #[error("Failed to get entry point selector by type`{0:?}`")]
    EntryPointType(EntryPointType),
    #[error("Failed to get entry point at array position `{0}`")]
    EntryPointIndex(usize),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
}
