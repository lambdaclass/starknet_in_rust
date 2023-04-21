use cairo_rs::types::relocatable::Relocatable;
use felt::Felt252;

// TODO: remove once used.
#[allow(dead_code)]
pub(crate) enum ResponseBody {
    StorageReadResponse { value: Option<Felt252> },
    Deploy(DeployResponse),
    CallContract(CallContractResponse),
    Failure(FailureReason),
}
#[allow(unused)]
pub(crate) struct SyscallResponse {
    /// The amount of gas left after the syscall execution.
    pub gas: u64,
    /// Syscall specific response fields.
    pub body: Option<ResponseBody>,
}

// ----------------------
//   Response objects
// ----------------------

pub struct DeployResponse {
    pub contract_address: Felt252,
    pub retdata_start: Relocatable,
    pub retdata_end: Relocatable,
}

pub struct FailureReason {
    pub retdata_start: Relocatable,
    pub retdata_end: Relocatable,
    // Syscall specific response fields.
    // TODO: this cause circular dependency
    //pub(crate) body: Option<ResponseBody>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CallContractResponse {
    pub retdata_start: Relocatable,
    pub retdata_end: Relocatable,
}
