use crate::core::errors::state_errors::StateError;
use crate::core::errors::hash_errors::HashError;
use cairo_vm::felt::Felt252;
use cairo_vm::{
    types::errors::math_errors::MathError,
    vm::errors::{
        hint_errors::HintError, memory_errors::MemoryError, vm_errors::VirtualMachineError,
    },
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyscallHandlerError {
    #[error("Unknown syscall: {0}")]
    UnknownSyscall(String),
    #[error("The selector '{0}' is not in the syscall handler's selector to syscall map")]
    SelectorNotInHandlerMap(String),
    #[error("The selector '{0}' does not have an associated cost")]
    SelectorDoesNotHaveAssociatedGas(String),
    #[error("Couldn't execute syscall: {0}")]
    ExecutionError(String),
    #[error("Couldn't convert from {0} to {1}")]
    Conversion(String, String),
    #[error("Couldn't compute hash")]
    HashError(#[from] HashError),
    #[error("Expected a struct of type: {0:?}, received: {1:?}")]
    ExpectedStruct(String, String),
    #[error("Unsopported address domain: {0}")]
    UnsopportedAddressDomain(Felt252),
    #[error("The deploy_from_zero field in the deploy system call must be 0 or 1, found: {0}")]
    DeployFromZero(usize),
    #[error("Hint not implemented: {0}")]
    NotImplemented(String),
    #[error("HintData is incorrect")]
    WrongHintData,
    #[error("Iterator is not empty")]
    IteratorNotEmpty,
    #[error("Iterator is empty")]
    IteratorEmpty,
    #[error("List is empty")]
    ListIsEmpty,
    #[error("{0} should be None")]
    ShouldBeNone(String),
    #[error("Unexpected construct retdata")]
    UnexpectedConstructorRetdata,
    #[error("Key not found")]
    KeyNotFound,
    #[error("The requested syscall read was not of the expected type")]
    InvalidSyscallReadRequest,
    #[error("tx_info_ptr is None")]
    TxInfoPtrIsNone,
    #[error("Virtual machine error: {0}")]
    VirtualMachine(#[from] VirtualMachineError),
    #[error("Memory error: {0}")]
    Memory(#[from] MemoryError),
    #[error("Expected a ptr but received invalid data")]
    InvalidTxInfoPtr,
    #[error("Could not compute hash")]
    ErrorComputingHash,
    #[error("Inconsistent start and end segment indices")]
    InconsistentSegmentIndices,
    #[error("Start offset greater than end offset")]
    StartOffsetGreaterThanEndOffset,
    #[error("Incorrect request in syscall {0}")]
    IncorrectSyscall(String),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    MathError(#[from] MathError),
    #[error(transparent)]
    Hint(#[from] HintError),
    #[error("Unsupported address domain: {0}")]
    UnsupportedAddressDomain(String),
    #[error("{0:?}")]
    CustomError(String),
}
