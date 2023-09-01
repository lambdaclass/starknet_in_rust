use crate::core::errors::hash_errors::HashError;
use cairo_vm::{
    types::errors::program_errors::ProgramError,
    vm::errors::{
        cairo_run_errors::CairoRunError, memory_errors::MemoryError, runner_errors::RunnerError,
        vm_errors::VirtualMachineError,
    },
};
use thiserror::Error;

use crate::syscalls::syscall_handler_errors::SyscallHandlerError;

#[derive(Debug, Error)]
pub enum ContractAddressError {
    #[error(transparent)]
    Program(#[from] ProgramError),
    #[error("Missing identifier: {0}")]
    MissingIdentifier(String),
    #[error("Nonexistent EntryPointType")]
    NonexistentEntryPointType,
    #[error("Invalid offset: {0}")]
    InvalidOffset(usize),
    #[error("Api version can't be None")]
    NoneApiVersion,
    #[error(transparent)]
    Memory(#[from] MemoryError),
    #[error("Index out of range")]
    IndexOutOfRange,
    #[error("Missing abi in sierra contract class")]
    MissingAbi,
    #[error(transparent)]
    CairoRunner(#[from] RunnerError),
    #[error(transparent)]
    CairoRun(#[from] CairoRunError),
    #[error(transparent)]
    VirtualMachine(#[from] VirtualMachineError),
    #[error("Could not remove suffix from builtin")]
    BuiltinSuffix,
    #[error(transparent)]
    SyscallHandler(#[from] SyscallHandlerError),
    #[error("Failed to cast {0} into {1}")]
    Cast(String, String),
    #[error("MaybeRelocatable is not an Int variant")]
    NoneIntMaybeRelocatable,
    #[error("Invalid program JSON, message: {0}")]
    InvalidProgramJson(String),
    #[error("Couldn't compute hash: {0}")]
    HashError(HashError),
}

impl From<HashError> for ContractAddressError {
    fn from(error: HashError) -> Self {
        ContractAddressError::HashError(error)
    }
}
