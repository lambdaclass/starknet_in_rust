use crate::{
    core::errors::{contract_address_errors::ContractAddressError, state_errors::StateError},
    syscalls::syscall_handler_errors::SyscallHandlerError,
    transaction::error::TransactionError,
};
use starknet_contract_class::EntryPointType;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParserError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    ContractAddress(#[from] ContractAddressError),
    #[error(transparent)]
    Syscall(#[from] SyscallHandlerError),
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
