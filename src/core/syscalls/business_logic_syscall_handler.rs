#![allow(dead_code)]

use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::vm_core::VirtualMachine,
};
use felt::Felt252;

use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{
                CallInfo, CallType, OrderedEvent, OrderedL2ToL1Message, TransactionExecutionContext,
            },
        },
        fact_state::state::ExecutionResourcesManager,
        state::{
            contract_storage_state::ContractStorageState,
            state_api::{State, StateReader},
        },
    },
    core::{
        errors::syscall_handler_errors::SyscallHandlerError,
        syscalls::syscall_request::FromPtr,
        syscalls::{
            syscall_request::SyscallRequest,
            syscall_response::{CallContractResponse, ResponseBody},
        },
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::EntryPointType,
    utils::{get_felt_range, Address},
};

use super::{
    syscall_handler::SyscallHandler, syscall_info::get_syscall_size_from_name,
    syscall_response::SyscallResponse,
};

//TODO Remove allow dead_code after merging to 0.11
#[allow(dead_code)]
#[derive(Debug)]
pub struct BusinessLogicSyscallHandler<'a, T: Default + State + StateReader> {
    pub(crate) tx_execution_context: TransactionExecutionContext,
    /// Events emitted by the current contract call.
    pub(crate) events: Vec<OrderedEvent>,
    /// A list of dynamically allocated segments that are expected to be read-only.
    pub(crate) read_only_segments: Vec<(Relocatable, MaybeRelocatable)>,
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) contract_address: Address,
    pub(crate) caller_address: Address,
    pub(crate) l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub(crate) general_config: StarknetGeneralConfig,
    pub(crate) tx_info_ptr: Option<MaybeRelocatable>,
    pub(crate) starknet_storage_state: ContractStorageState<'a, T>,
    pub(crate) internal_calls: Vec<CallInfo>,
    pub(crate) expected_syscall_ptr: Relocatable,
    pub(crate) entry_point: ExecutionEntryPoint,
}

impl<'a, T: Default + State + StateReader> BusinessLogicSyscallHandler<'a, T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: &'a mut T,
        resources_manager: ExecutionResourcesManager,
        expected_syscall_ptr: Relocatable,
        contract_address: Address,
        caller_address: Address,
        general_config: StarknetGeneralConfig,
        tx_execution_context: TransactionExecutionContext,
        entry_point: ExecutionEntryPoint,
    ) -> Self {
        let events = Vec::new();
        let read_only_segments = Vec::new();
        let l2_to_l1_messages = Vec::new();
        let tx_info_ptr = None;
        let starknet_storage_state = ContractStorageState::new(state, contract_address.clone());

        let internal_calls = Vec::new();

        BusinessLogicSyscallHandler {
            tx_execution_context,
            events,
            read_only_segments,
            resources_manager,
            contract_address,
            caller_address,
            l2_to_l1_messages,
            general_config,
            tx_info_ptr,
            starknet_storage_state,
            internal_calls,
            expected_syscall_ptr,
            entry_point,
        }
    }

    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }

    fn allocate_segment(
        &mut self,
        vm: &mut VirtualMachine,
        data: Vec<MaybeRelocatable>,
    ) -> Result<Relocatable, SyscallHandlerError> {
        let segment_start = vm.add_memory_segment();
        let segment_end = vm.write_arg(segment_start, &data)?;
        let sub = segment_end.sub(&segment_start.to_owned().into())?;
        let segment = (segment_start.to_owned(), sub);
        self.read_only_segments.push(segment);

        Ok(segment_start)
    }

    fn call_contract_helper(
        &mut self,
        vm: &mut VirtualMachine,
        remaining_gas: u64,
        execution_entry_point: ExecutionEntryPoint,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        let result = execution_entry_point
            .execute(
                self.starknet_storage_state.state,
                &self.general_config,
                &mut self.resources_manager,
                &self.tx_execution_context,
            )
            .map_err(|err| SyscallHandlerError::ExecutionError(err.to_string()))?;

        let retdata_maybe_reloc = result
            .retdata
            .clone()
            .into_iter()
            .map(|item| MaybeRelocatable::from(Felt252::new(item)))
            .collect::<Vec<MaybeRelocatable>>();

        let retdata_start = self.allocate_segment(vm, retdata_maybe_reloc)?;
        let retdata_end = (retdata_start + result.retdata.len())?;

        self.internal_calls.push(result);

        //TODO: remaining_gas -= result.gas_consumed
        let gas = remaining_gas;
        let body = Some(ResponseBody::CallContract(CallContractResponse {
            retdata_start,
            retdata_end,
        }));

        Ok(SyscallResponse { gas, body })
    }

    fn syscall_storage_write(&mut self, key: Felt252, value: Felt252) {
        self.starknet_storage_state.write(&key.to_le_bytes(), value)
    }
}

impl<'a, T: Default + State + StateReader> SyscallHandler for BusinessLogicSyscallHandler<'a, T> {
    fn storage_write(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        let request = if let SyscallRequest::StorageWrite(request) =
            self.read_and_validate_syscall_request("storage_write", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedStorageWriteSyscall);
        };

        if request.reserved != 0.into() {
            return Err(SyscallHandlerError::UnsopportedAddressDomain(
                request.reserved,
            ));
        }

        self.syscall_storage_write(request.key, request.value);

        Ok(SyscallResponse {
            gas: remaining_gas,
            body: None,
        })
    }

    fn call_contract(
        &mut self,
        vm: &mut VirtualMachine,
        request: SyscallRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        let request = match request {
            SyscallRequest::CallContract(request) => request,
            _ => return Err(SyscallHandlerError::ExpectedCallContractRequest),
        };

        let calldata = get_felt_range(vm, request.calldata_start, request.calldata_end)?;
        let execution_entry_point = ExecutionEntryPoint::new(
            request.contract_address,
            calldata,
            request.selector,
            self.caller_address.clone(),
            EntryPointType::External,
            Some(CallType::Call),
            None,
        );

        self.call_contract_helper(vm, remaining_gas, execution_entry_point)
    }

    fn read_syscall_request(
        &self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        match syscall_name {
            "storage_write" => {
                super::syscall_request::StorageWriteRequest::from_ptr(vm, syscall_ptr)
            }
            _ => Err(SyscallHandlerError::UnknownSyscall(
                syscall_name.to_string(),
            )),
        }
    }

    fn send_message_to_l1(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
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
        Ok(SyscallResponse {
            gas: remaining_gas,
            body: None,
        })
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

    fn library_call(
        &mut self,
        remaining_gas: u64,
        vm: &mut VirtualMachine,
        library_call_request: SyscallRequest,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        let request = match library_call_request {
            SyscallRequest::LibraryCall(request) => request,
            _ => return Err(SyscallHandlerError::ExpectedLibraryCallRequest),
        };

        let calldata = get_felt_range(vm, request.calldata_start, request.calldata_end)?;
        let execution_entry_point = ExecutionEntryPoint::new(
            self.entry_point.contract_address.clone(),
            calldata,
            request.selector,
            self.caller_address.clone(),
            EntryPointType::External,
            Some(CallType::Delegate),
            None,
        );

        self.call_contract_helper(vm, remaining_gas, execution_entry_point)
    }
}
