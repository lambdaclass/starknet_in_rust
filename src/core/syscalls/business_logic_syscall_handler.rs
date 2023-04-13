use cairo_rs::types::relocatable::Relocatable;

use crate::business_logic::{
    execution::objects::{OrderedEvent, TransactionExecutionContext},
    fact_state::state::ExecutionResourcesManager,
};

#[allow(unused)]
pub struct BusinessLogicSyscallHandler {
    pub(crate) events: Vec<OrderedEvent>,
    pub(crate) expected_syscall_ptr: Relocatable,
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) tx_execution_context: TransactionExecutionContext,
}

impl BusinessLogicSyscallHandler {
    #[allow(unused)]
    /// Increments the syscall count for a given `syscall_name` by 1.
    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }
}
