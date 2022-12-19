use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
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
    #[error("The deploy_from_zero field in the deploy system call must be 0 or 1")]
    DeployFromZero,
    #[error("Hint not implemented")]
    NotImplemented,
    #[error("HintData is incorrect")]
    WrongHintData,
    #[error("Unknown hint")]
    UnknownHint,
}
