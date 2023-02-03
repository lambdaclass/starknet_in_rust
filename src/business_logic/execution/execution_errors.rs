use std::error;

use cairo_rs::{
    types::relocatable::Relocatable,
    vm::errors::{
        cairo_run_errors::CairoRunError, memory_errors::MemoryError, runner_errors::RunnerError,
        trace_errors::TraceError, vm_errors::VirtualMachineError,
    },
};
use felt::Felt;
use thiserror::Error;

use crate::{core::errors, starknet_runner::starknet_runner_error::StarknetRunnerError};
#[derive(Debug, Error)]
pub enum ExecutionError {
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
    #[error("Could not create cairo runner")]
    FailToCreateCairoRunner,
    #[error("contract address {0:?} not deployed")]
    NotDeployedContract([u8; 32]),
    #[error("error allocating memory segment")]
    ErrorAllocatingSegment,
    #[error("Non-unique entry points are not possible in a ContractClass object")]
    NonUniqueEntryPoint,
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
    #[error("Expected and int value got a Relocatable")]
    NotAnInt,
    #[error("Out of bounds write to a read-only segment.")]
    OutOfBound,
    #[error(transparent)]
    TraceException(#[from] TraceError),
    #[error(transparent)]
    MemoryException(#[from] MemoryError),
    #[error("Expected Relocatable; found None")]
    InvalidInitialFp,
    #[error("Could not convert memory values array into felts")]
    InvalidMemoryValues,
    #[error(transparent)]
    VmException(#[from] VirtualMachineError),
    #[error(transparent)]
    CairoRunnerException(#[from] CairoRunError),
    #[error(transparent)]
    RunnerException(#[from] RunnerError),
    #[error(transparent)]
    StarknetRunnerException(#[from] StarknetRunnerError),
}
