use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};

use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallType, TransactionExecutionContext},
        },
        fact_state::state::ExecutionResourcesManager,
        state::{
            contract_storage_state::ContractStorageState,
            state_api::{State, StateReader},
        },
    },
    core::{
        errors::syscall_handler_errors::SyscallHandlerError,
        syscalls::syscall_request::SyscallRequest,
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::EntryPointType,
    utils::{get_felt_range, Address},
};

use super::{
    syscall_handler::SyscallHandler, syscall_info::get_syscall_size_from_name,
    syscall_response::SyscallResponse,
};

pub struct BusinessLogicSyscallHandler<'a, T: Default + State + StateReader> {
    pub(crate) tx_execution_context: TransactionExecutionContext,
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) expected_syscall_ptr: Relocatable,
    pub(crate) caller_address: Address,
    pub(crate) general_config: StarknetGeneralConfig,
    pub(crate) starknet_storage_state: ContractStorageState<'a, T>,
}

impl<'a, T: Default + State + StateReader> BusinessLogicSyscallHandler<'a, T> {
    pub fn new(
        tx_execution_context: TransactionExecutionContext,
        state: &'a mut T,
        contract_address: Address,
        resources_manager: ExecutionResourcesManager,
        expected_syscall_ptr: Relocatable,
        caller_address: Address,
        general_config: StarknetGeneralConfig,
    ) -> Self {
        let starknet_storage_state = ContractStorageState::new(state, contract_address);
        Self {
            tx_execution_context,
            resources_manager,
            expected_syscall_ptr,
            caller_address,
            general_config,
            starknet_storage_state,
        }
    }

    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }
}

impl<'a, T: Default + State + StateReader> SyscallHandler for BusinessLogicSyscallHandler<'a, T> {
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

        let calldata = get_felt_range(vm, request.calldata_start, request.calldata_end)?;
        let contract_address = request.contract_address;
        let caller_address = &self.caller_address;
        let call_type = Some(CallType::Call);

        let call = ExecutionEntryPoint::new(
            contract_address,
            calldata,
            request.selector,
            caller_address.clone(),
            EntryPointType::External,
            call_type,
            None,
        );

        let _callinfo = call
            .execute(
                self.starknet_storage_state.state,
                &self.general_config,
                &mut self.resources_manager,
                &self.tx_execution_context,
            )
            .map_err(|err| SyscallHandlerError::ExecutionError(err.to_string()))?;

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
