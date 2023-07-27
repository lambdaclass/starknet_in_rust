use crate::core::errors::hash_errors::HashError;
use crate::core::errors::state_errors::StateError;
use cairo_vm::felt::Felt252;
use cairo_vm::{
    types::errors::math_errors::MathError,
    vm::errors::{
        hint_errors::HintError, memory_errors::MemoryError, vm_errors::VirtualMachineError,
    },
};
use thiserror::Error;

// SyscallHandlerError enum handles error that may occur in syscall handling
#[derive(Debug, Error)]
pub enum SyscallHandlerError {
    // Raise when an unknown syscall is encountered
    #[error("Unknown syscall: {0}")]
    UnknownSyscall(String),

    // Raise when the selector is not in the handler's map
    #[error("The selector '{0}' is not in the syscall handler's selector to syscall map")]
    SelectorNotInHandlerMap(String),

    // Raise when the selector does not have an associated gas cost
    #[error("The selector '{0}' does not have an associated cost")]
    SelectorDoesNotHaveAssociatedGas(String),

    // Raised when a syscall fails to execute
    #[error("Couldn't execute syscall: {0}")]
    ExecutionError(String),

    // Raised when a conversion fails
    #[error("Couldn't convert from {0} to {1}")]
    Conversion(String, String),

    // Raised when an hash error occured. Wraps a HashError
    #[error("Couldn't compute hash: {0}")]
    HashError(#[from] HashError),

    // Raised when an unexpected struct type is encountered
    #[error("Expected a struct of type: {0:?}, received: {1:?}")]
    ExpectedStruct(String, String),

    // Raised when an unsupported address domain is used
    #[error("Unsupported address domain: {0}")]
    UnsopportedAddressDomain(Felt252),

    // Raised when the 'deploy_from_zero' field in the deploy system call is not 0 or 1
    #[error("The deploy_from_zero field in the deploy system call must be 0 or 1, found: {0}")]
    DeployFromZero(usize),

    // Raised when a not implemented hint is encountered
    #[error("Hint not implemented: {0}")]
    NotImplemented(String),

    // Raised when the data for a hint is incorrect
    #[error("HintData is incorrect")]
    WrongHintData,

    // Raised when an iterator should be empty but is not
    #[error("Iterator is not empty")]
    IteratorNotEmpty,

    // Raised when an iterator should not be empty but is
    #[error("Iterator is empty")]
    IteratorEmpty,

    // Raised when a list should not be empty but is
    #[error("List is empty")]
    ListIsEmpty,

    // Raised when a field or variable should be None but is not
    #[error("{0} should be None")]
    ShouldBeNone(String),

    // Raised when a construct retdata is unexpectedly encountered
    #[error("Unexpected construct retdata")]
    UnexpectedConstructorRetdata,

    // Raised when a required key is not found
    #[error("Key not found")]
    KeyNotFound,

    // Raised when the type of a syscall read request is unexpected
    #[error("The requested syscall read was not of the expected type")]
    InvalidSyscallReadRequest,

    // Raised when transaction info pointer is None when it should not be
    #[error("tx_info_ptr is None")]
    TxInfoPtrIsNone,

    // Raised when a virtual machine error occurs. Wraps a VirtualMachineError
    #[error("Virtual machine error: {0}")]
    VirtualMachine(#[from] VirtualMachineError),

    // Raised when a memory error occurs. Wraps a MemoryError
    #[error("Memory error: {0}")]
    Memory(#[from] MemoryError),

    // Raised when an invalid transaction info pointer is encountered
    #[error("Expected a ptr but received invalid data")]
    InvalidTxInfoPtr,

    // Raised when a hash cannot be computed
    #[error("Could not compute hash")]
    ErrorComputingHash,

    // Raised when start and end segment indices are inconsistent
    #[error("Inconsistent start and end segment indices")]
    InconsistentSegmentIndices,

    // Raised when start offset is greater than end offset
    #[error("Start offset greater than end offset")]
    StartOffsetGreaterThanEndOffset,

    // Raised when a syscall is incorrectly constructed
    #[error("Incorrect request in syscall {0}")]
    IncorrectSyscall(String),

    // Raised when a state error occurs. Wraps a StateError
    #[error(transparent)]
    State(#[from] StateError),

    // Raised when a math error occurs. Wraps a MathError
    #[error(transparent)]
    MathError(#[from] MathError),

    // Raised when a hint error occurs. Wraps a HintError
    #[error(transparent)]
    Hint(#[from] HintError),

    // Raised when an unsupported address domain is used
    #[error("Unsupported address domain: {0}")]
    UnsupportedAddressDomain(String),

    // Raised for general, custom errors
    #[error("{0:?}")]
    CustomError(String),
}
