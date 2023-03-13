use crate::{
    business_logic::execution::os_usage::OsResources,
    core::errors::{
        contract_address_errors::ContractAddressError, state_errors::StateError,
        syscall_handler_errors::SyscallHandlerError,
    },
    definitions::transaction_type::TransactionType,
    starknet_runner::starknet_runner_error::StarknetRunnerError,
    starkware_utils::starkware_errors::StarkwareError,
};
use cairo_rs::{
    types::relocatable::Relocatable,
    vm::errors::{
        cairo_run_errors::CairoRunError, memory_errors::MemoryError, runner_errors::RunnerError,
        trace_errors::TraceError, vm_errors::VirtualMachineError,
    },
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("Invalid felt convertion to u64")]
    InvalidFeltConversion,
    #[error("{0}")]
    InvalidNonce(String),
    #[error("Invalid transaction nonce. Expected: {0} got {1}")]
    InvalidTransactionNonce(String, String),
    #[error("{0}")]
    StarknetError(String),
    #[error("{0}")]
    FeeError(String),
    #[error("Cairo resource names must be contained in fee weights dict")]
    ResourcesError,
    #[error("Could not calculate resources")]
    ResourcesCalculation,
    #[error("{0}")]
    RunValidation(String),
    #[error("Missing contract class storage")]
    MissingClassStorage,
    #[error("Unimplemented state updates")]
    NotImplemented,
    #[error("{0}")]
    InvokeExecution(String),
    #[error(transparent)]
    ContractAddress(#[from] ContractAddressError),
    #[error(transparent)]
    Syscall(#[from] SyscallHandlerError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("Calling other contracts during validate execution is forbidden")]
    UnauthorizedActionOnValidate,
    #[error("Class hash {0:?} already declared")]
    ClassAlreadyDeclared([u8; 32]),
    #[error(transparent)]
    Starkware(#[from] StarkwareError),
    #[error("Missing field for TxStruct")]
    MissingTxStructField,
    #[error("Expected an int value but get wrong data type")]
    NotAFeltValue,
    #[error("Expected a relocatable value but get wrong data type")]
    NotARelocatableValue,
    #[error("Error converting from {0} to {1}")]
    ErrorInDataConversion(String, String),
    #[error("Unexpected holes in the event order")]
    UnexpectedHolesInEventOrder,
    #[error("Unexpected holes in the L2-to-L1 message order.")]
    UnexpectedHolesL2toL1Messages,
    #[error("Call type {0} not implemented")]
    CallTypeNotImplemented(String),
    #[error("Attemp to return class hash with incorrect call type")]
    CallTypeIsNotDelegate,
    #[error("Attemp to return code address when is None")]
    AttempToUseNoneCodeAddress,
    #[error("error recovering class hash from storage")]
    FailToReadClassHash,
    #[error("error while fetching redata {0}")]
    RetdataError(String),
    #[error("Missing contract class after fetching")]
    MissigContractClass,
    #[error("contract address {0:?} not deployed")]
    NotDeployedContract([u8; 32]),
    #[error("error allocating memory segment")]
    ErrorAllocatingSegment,
    #[error("Non-unique entry points are not possible in a ContractClass object")]
    NonUniqueEntryPoint,
    #[error("Requested entry point was not found")]
    EntryPointNotFound,
    #[error("Ptr result diverges after calculate final stacks")]
    OsContextPtrNotEqual,
    #[error("Illegal OS ptr offset")]
    IllegalOsPtrOffset,
    #[error("Invalid pointer fetched from memory expected maybe relocatable but got None")]
    InvalidPtrFetch,
    #[error("Segment base pointer must be zero; got {0}")]
    InvalidSegBasePtrOffset(usize),
    #[error("Invalid segment size; expected usize but got None")]
    InvalidSegmentSize,
    #[error("Invalid stop pointer for segment; expected {0}, found {1}")]
    InvalidStopPointer(Relocatable, Relocatable),
    #[error("Invalid entry point types")]
    InvalidEntryPoints,
    #[error("Expected and int value got a Relocatable")]
    NotAnInt,
    #[error("Out of bounds write to a read-only segment.")]
    OutOfBound,
    #[error("Call to another contract has been done")]
    InvalidContractCall,
    #[error(transparent)]
    TraceException(#[from] TraceError),
    #[error(transparent)]
    MemoryException(#[from] MemoryError),
    #[error("Expected Relocatable; found None")]
    InvalidInitialFp,
    #[error("Transaction context is invalid")]
    InvalidTxContext,
    #[error("{0}")]
    FeeCalculation(String),
    #[error(transparent)]
    Vm(#[from] VirtualMachineError),
    #[error(transparent)]
    CairoRunner(#[from] CairoRunError),
    #[error(transparent)]
    Runner(#[from] RunnerError),
    #[error(transparent)]
    StarknetRunner(#[from] StarknetRunnerError),
    #[error("Transaction type {0:?} not found in OsResources: {1:?}")]
    NoneTransactionType(TransactionType, OsResources),
}
