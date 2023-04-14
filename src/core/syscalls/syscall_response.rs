use cairo_rs::types::relocatable::Relocatable;

pub(crate) enum ResponseBody {
    CallContract(CallContractResponse),
}

#[allow(unused)]
pub(crate) struct SyscallResponse {
    /// The amount of gas left after the syscall execution.
    pub(crate) gas: u64,
    /// Syscall specific response fields.
    pub(crate) body: Option<ResponseBody>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CallContractResponse {
    pub(crate) retdata_start: Relocatable,
    pub(crate) retdata_end: Relocatable,
}
