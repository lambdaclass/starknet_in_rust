use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum SyscallHandlerError {
    #[error("Missing Member")]
    MissingMember,
    #[error("Missing Identifiers")]
    MissingIdentifiers,
    #[error("Missing selector value")]
    MissingSelector,
    #[error("Missing file syscalls.json")]
    MissingSyscallsJsonFile,
    #[error("Unknown syscall")]
    UnknownSyscall,
    #[error("invalid pointer")]
    SegmentationFault,
    #[error("Couldn't convert BigInt to usize")]
    BigintToUsizeFail,
    #[error("Couldn't compure hash")]
    FailToComputeHash,
    #[error("Expected DesployRequestStruct")]
    ExpectedDeployRequestStruct,
    #[error("Expected EmitEventStruct")]
    ExpectedEmitEventStruct,
    #[error("Expected GetCallerAddressRequest")]
    ExpectedGetCallerAddressRequest,
    #[error("Expected SendMessageToL1")]
    ExpectedSendMessageToL1,
    #[error("The deploy_from_zero field in the deploy system call must be 0 or 1, found: {0}")]
    DeployFromZero(usize),
    #[error("Hint not implemented")]
    NotImplemented,
    #[error("HintData is incorrect")]
    WrongHintData,
    #[error("Unknown hint")]
    UnknownHint,
    #[error("The requested syscall read was not of the expected type")]
    InvalidSyscallReadRequest,
    #[error("Virtual machine error: {0}")]
    VirtualMachineError(#[from] VirtualMachineError),
}
