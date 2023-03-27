use crate::{
    business_logic::execution::os_usage::OsResources,
    core::errors::{
        contract_address_errors::ContractAddressError, state_errors::StateError,
        syscall_handler_errors::SyscallHandlerError,
    },
    definitions::transaction_type::TransactionType,
    starknet_runner::starknet_runner_error::StarknetRunnerError,
    starkware_utils::starkware_errors::StarkwareError,
    utils::ClassHash,
};
use cairo_rs::{
    types::{errors::math_errors::MathError, relocatable::Relocatable},
    vm::errors::{
        cairo_run_errors::CairoRunError, memory_errors::MemoryError, runner_errors::RunnerError,
        trace_errors::TraceError, vm_errors::VirtualMachineError,
    },
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("Nonce is None")]
    MissingNonce,
    #[error("An InvokeFunction transaction (version != 0) must have a nonce.")]
    InvokeFunctionNonZeroMissingNonce,
    #[error("An InvokeFunction transaction (version = 0) cannot have a nonce.")]
    InvokeFunctionZeroHasNonce,
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
    #[error(transparent)]
    ContractAddress(#[from] ContractAddressError),
    #[error(transparent)]
    Syscall(#[from] SyscallHandlerError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("Calling other contracts during validate execution is forbidden")]
    UnauthorizedActionOnValidate,
    #[error("Class hash {0:?} already declared")]
    ClassAlreadyDeclared(ClassHash),
    #[error(transparent)]
    Starkware(#[from] StarkwareError),
    #[error("Expected a relocatable value but got an integer")]
    NotARelocatableValue,
    #[error("Unexpected holes in the event order")]
    UnexpectedHolesInEventOrder,
    #[error("Unexpected holes in the L2-to-L1 message order.")]
    UnexpectedHolesL2toL1Messages,
    #[error("Attemp to return class hash with incorrect call type")]
    CallTypeIsNotDelegate,
    #[error("Attemp to return code address when it is None")]
    AttempToUseNoneCodeAddress,
    #[error("Error recovering class hash from storage")]
    FailToReadClassHash,
    #[error("Missing contract class after fetching")]
    MissigContractClass,
    #[error("Contract address {0:?} is not deployed")]
    NotDeployedContract(ClassHash),
    #[error("Non-unique entry points are not possible in a ContractClass object")]
    NonUniqueEntryPoint,
    #[error("Requested entry point was not found")]
    EntryPointNotFound,
    #[error("Ptr result diverges after calculating final stacks")]
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
    #[error("Expected an int value got a Relocatable")]
    NotAnInt,
    #[error("Out of bounds write to a read-only segment.")]
    OutOfBound,
    #[error("Call to another contract has been done")]
    InvalidContractCall,
    #[error(transparent)]
    TraceException(#[from] TraceError),
    #[error(transparent)]
    MemoryException(#[from] MemoryError),
    #[error("Missing initial_fp")]
    MissingInitialFp,
    #[error("Transaction context is invalid")]
    InvalidTxContext,
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
    #[error(transparent)]
    MathError(#[from] MathError),
}
