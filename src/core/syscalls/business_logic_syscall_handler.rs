use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};

use crate::{
    business_logic::fact_state::state::ExecutionResourcesManager,
    core::{
        errors::syscall_handler_errors::SyscallHandlerError,
        syscalls::syscall_request::SyscallRequest,
    },
    utils::get_felt_range,
};

use super::{
    syscall_handler::SyscallHandler, syscall_info::get_syscall_size_from_name,
    syscall_response::SyscallResponse,
};

pub struct BusinessLogicSyscallHandler {
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) expected_syscall_ptr: Relocatable,
}

impl BusinessLogicSyscallHandler {
    pub fn new(
        resources_manager: ExecutionResourcesManager,
        expected_syscall_ptr: Relocatable,
    ) -> Self {
        Self {
            resources_manager,
            expected_syscall_ptr,
        }
    }

    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }
}

impl SyscallHandler for BusinessLogicSyscallHandler {
    #[allow(irrefutable_let_patterns)]
    fn call_contract(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
        _remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        let request = if let SyscallRequest::CallContract(request) =
            self.read_and_validate_syscall_request("call_contract", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedCallContractRequest);
        };

        let _calldata = get_felt_range(vm, request.calldata_start, request.calldata_end)?;
        /*
        calldata = self._get_felt_range(
            start_addr=request.calldata_start, end_addr=request.calldata_end
        )
        class_hash: Optional[int] = None
        if syscall_name == "call_contract":
            contract_address = cast_to_int(request.contract_address)
            caller_address = self.entry_point.contract_address
            call_type = CallType.CALL
        elif syscall_name == "library_call":
            contract_address = self.entry_point.contract_address
            caller_address = self.entry_point.caller_address
            call_type = CallType.DELEGATE
            class_hash = cast_to_int(request.class_hash)
        else:
            raise NotImplementedError(f"Unsupported call type {syscall_name}.")

        call = self.execute_entry_point_cls(
            call_type=call_type,
            contract_address=contract_address,
            entry_point_selector=cast_to_int(request.selector),
            entry_point_type=EntryPointType.EXTERNAL,
            calldata=calldata,
            caller_address=caller_address,
            initial_gas=remaining_gas,
            class_hash=class_hash,
            code_address=None,
        )

        return self.execute_entry_point(call=call)
        */
        todo!()
    }

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
}
