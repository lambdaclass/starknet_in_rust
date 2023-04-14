pub(crate) enum ResponseBody {}

#[allow(unused)]
pub(crate) struct SyscallResponse {
    /// The amount of gas left after the syscall execution.
    gas: u64,
    /// Syscall specific response fields.
    body: Option<ResponseBody>,
}
