use cairo_rs::{
    types::errors::program_errors::ProgramError,
    vm::errors::{
        cairo_run_errors::CairoRunError, memory_errors::MemoryError, runner_errors::RunnerError,
        vm_errors::VirtualMachineError,
    },
};
use felt::Felt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractAddressError {
    #[error(transparent)]
    Program(#[from] ProgramError),
    #[error("Missing identifier: {0}")]
    MissingIdentifier(String),
    #[error("None existing EntryPointType")]
    NoneExistingEntryPointType,
    #[error("Invalid offset: {0}")]
    InvalidOffset(Felt),
    #[error("Api version can't be None")]
    NoneApiVersion,
    #[error(transparent)]
    Memory(#[from] MemoryError),
    #[error("Index out of range")]
    IndexOutOfRange,
    #[error("Expected integer variant of MaybeRelocatable")]
    ExpectedInteger,
    #[error("Failed to calculate contract address from hash with error: {0}")]
    ContractAddressFromHash(String),
    #[error(transparent)]
    CairoRunner(#[from] RunnerError),
    #[error(transparent)]
    CairoRun(#[from] CairoRunError),
    #[error(transparent)]
    VirtualMachine(#[from] VirtualMachineError),
}
