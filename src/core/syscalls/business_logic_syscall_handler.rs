use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};

use crate::{
    business_logic::{
        execution::objects::{OrderedL2ToL1Message, TransactionExecutionContext},
        fact_state::state::ExecutionResourcesManager,
    },
    core::errors::syscall_handler_errors::SyscallHandlerError,
    utils::get_felt_range,
};

use super::{
    syscall_handler::SyscallHandler, syscall_info::get_syscall_size_from_name,
    syscall_request::SyscallRequest,
};

pub struct BusinessLogicSyscallHandler {
    pub(crate) tx_execution_context: TransactionExecutionContext,
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub(crate) expected_syscall_ptr: Relocatable,
}

impl BusinessLogicSyscallHandler {
    pub fn new(
        tx_execution_context: TransactionExecutionContext,
        resources_manager: ExecutionResourcesManager,
        syscall_ptr: Relocatable,
    ) -> Self {
        BusinessLogicSyscallHandler {
            tx_execution_context,
            resources_manager,
            l2_to_l1_messages: Vec::new(),
            expected_syscall_ptr: syscall_ptr,
        }
    }

    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }
}

impl SyscallHandler for BusinessLogicSyscallHandler {
    fn read_and_validate_syscall_request(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        self.increment_syscall_count(syscall_name);
        let syscall_request = self.read_syscall_request(syscall_name, vm, syscall_ptr)?;

        self.expected_syscall_ptr.offset += get_syscall_size_from_name(syscall_name);
        Ok(syscall_request)
    }

    //TODO remove allow irrefutable_let_patterns
    #[allow(irrefutable_let_patterns)]
    fn send_message_to_l1(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let request = if let SyscallRequest::SendMessageToL1(request) =
            self.read_and_validate_syscall_request("send_message_to_l1", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedSendMessageToL1);
        };

        let payload = get_felt_range(vm, request.payload_start, request.payload_end)?;

        self.l2_to_l1_messages.push(OrderedL2ToL1Message::new(
            self.tx_execution_context.n_sent_messages,
            request.to_address,
            payload,
        ));

        // Update messages count.
        self.tx_execution_context.n_sent_messages += 1;
        Ok(())
    }
}
