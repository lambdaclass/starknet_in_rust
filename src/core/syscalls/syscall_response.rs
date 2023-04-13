pub enum ResponseBody {}

#[allow(unused)]
pub struct SyscallResponse {
    /// The amount of gas left after the syscall execution.
    gas: u64,
    /// If the syscall succeeded.
    failure_flag: bool,
    /// Syscall specific response fields.
    syscall_response: ResponseBody,
}
