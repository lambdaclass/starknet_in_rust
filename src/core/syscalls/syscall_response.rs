pub(crate) enum ResponseBody {}

#[allow(unused)]
pub(crate) struct SyscallResponse {
    /// The amount of gas left after the syscall execution.
    pub(crate) gas: u64,
    /// Syscall specific response fields.
    pub(crate) body: Option<ResponseBody>,
}
