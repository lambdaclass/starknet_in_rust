use super::state_errors::StateError;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum SyscallHandlerError {
    #[error("Missing Member")]
    MissingMember,
    #[error("Missing Identifiers")]
    MissingIdentifiers,
    #[error("Missing selector value")]
    MissingSelector,
    #[error("Unknown syscall: {0}")]
    UnknownSyscall(String),
    #[error("invalid pointer")]
    SegmentationFault,
    #[error("Couldn't convert Felt to usize")]
    FeltToUsizeFail,
    #[error("Couldn't convert Felt to u64")]
    FeltToU64Fail,
    #[error("Couldn't compute hash")]
    FailToComputeHash,
    #[error("Expected DesployRequestStruct")]
    ExpectedDeployRequestStruct,
    #[error("Expected EmitEventStruct")]
    ExpectedEmitEventStruct,
    #[error("Expected GetCallerAddressRequest")]
    ExpectedGetCallerAddressRequest,
    #[error("Expected SendMessageToL1")]
    ExpectedSendMessageToL1,
    #[error("Expected GetBlockTimestampRequest")]
    ExpectedGetBlockTimestampRequest,
    #[error("Expected StorageReadRequest")]
    ExpectedStorageReadRequest,
    #[error("The deploy_from_zero field in the deploy system call must be 0 or 1, found: {0}")]
    DeployFromZero(usize),
    #[error("Hint not implemented")]
    NotImplemented,
    #[error("HintData is incorrect")]
    WrongHintData,
    #[error("Unknown hint")]
    UnknownHint,
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
    #[error("Error writing arguments")]
    WriteArg,
    #[error("Key not found")]
    KeyNotFound,
    #[error("The requested syscall read was not of the expected type")]
    InvalidSyscallReadRequest,
    #[error("tx_info_ptr is None")]
    TxInfoPtrIsNone,
    #[error("Virtual machine error: {0}")]
    VirtualMachineError(#[from] VirtualMachineError),
    #[error("Expected GetContractAddressRequest")]
    ExpectedGetContractAddressRequest,
    #[error("Expected GetSequencerAddressRequest")]
    ExpectedGetSequencerAddressRequest,
    #[error("Expected CallContractRequest")]
    ExpectedCallContract,
    #[error("Expected MaybeRelocatable")]
    ExpectedMaybeRelocatable,
    #[error("Expected MaybeRelocatable::Int")]
    ExpectedMaybeRelocatableInt,
    #[error("Memory error: {0}")]
    MemoryError(String),
    #[error("Expected GetTxSignatureRequest")]
    ExpectedGetTxSignatureRequest,
    #[error("Expected a ptr but received invalid data")]
    InvalidTxInfoPtr,
    #[error("could not convert felt to u64")]
    InvalidFeltConversion,
    #[error("Could not compute hash")]
    ErrorComputingHash,
    #[error(transparent)]
    StateError(#[from] StateError),
}
