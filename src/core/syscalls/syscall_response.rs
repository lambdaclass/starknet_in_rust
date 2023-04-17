use cairo_rs::types::relocatable::Relocatable;
use felt::Felt252;

pub enum ResponseBody {
    Deploy(DeployResponse),
    Failure(FailureReason),

#[allow(unused)]
pub(crate) struct SyscallResponse {
    /// The amount of gas left after the syscall execution.
    pub gas: u64,
    /// Syscall specific response fields.
    pub body: ResponseBody,
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
    body: Option<ResponseBody>,
}
