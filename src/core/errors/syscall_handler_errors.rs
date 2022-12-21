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
}
