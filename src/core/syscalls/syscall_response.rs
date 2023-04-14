use felt::Felt252;

#[allow(dead_code)]
pub(crate) enum ResponseBody {
    StorageReadResponse { value: Option<Felt252> },
}

#[allow(unused)]
pub(crate) struct SyscallResponse {
    /// The amount of gas left after the syscall execution.
    pub(crate) gas: u64,
    /// Syscall specific response fields.
    pub(crate) body: Option<ResponseBody>,
}
