#![allow(dead_code)]

use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::vm_core::VirtualMachine,
};
use felt::Felt252;

use crate::{
    business_logic::{
        execution::objects::{
            CallInfo, OrderedEvent, OrderedL2ToL1Message, TransactionExecutionContext,
        },
        fact_state::state::ExecutionResourcesManager,
        state::{
            contract_storage_state::ContractStorageState,
            state_api::{State, StateReader},
        },
    },
    core::{
        errors::syscall_handler_errors::SyscallHandlerError, syscalls::syscall_request::FromPtr,
    },
    definitions::general_config::StarknetGeneralConfig,
    utils::{get_felt_range, Address},
};

use super::{syscall_handler::SyscallHandler, syscall_request::SyscallRequest};
use super::{syscall_info::get_syscall_size_from_name, syscall_response::SyscallResponse};

//TODO Remove allow dead_code after merging to 0.11
#[allow(dead_code)]
#[derive(Debug)]
pub struct BusinessLogicSyscallHandler<'a, T: State + StateReader> {
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
}

impl<'a, T: Default + State + StateReader> BusinessLogicSyscallHandler<'a, T> {
    pub fn new(
        tx_execution_context: TransactionExecutionContext,
        state: &'a mut T,
        resources_manager: ExecutionResourcesManager,
        caller_address: Address,
        contract_address: Address,
        general_config: StarknetGeneralConfig,
        syscall_ptr: Relocatable,
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
            expected_syscall_ptr: syscall_ptr,
        }
    }

    /// Increments the syscall count for a given `syscall_name` by 1.
    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }

    fn syscall_storage_write(&mut self, key: Felt252, value: Felt252) {
        self.starknet_storage_state.write(&key.to_le_bytes(), value)
    }
}

impl<'a, T> SyscallHandler for BusinessLogicSyscallHandler<'a, T>
where
    T: Default + State + StateReader,
{
    fn emit_event(
        &mut self,
        remaining_gas: u64,
        vm: &VirtualMachine,
        request: SyscallRequest,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        let request = match request {
            SyscallRequest::EmitEvent(emit_event_struct) => emit_event_struct,
            _ => return Err(SyscallHandlerError::InvalidSyscallReadRequest),
        };

        let order = self.tx_execution_context.n_emitted_events;
        let keys: Vec<Felt252> = get_felt_range(vm, request.keys_start, request.keys_end)?;
        let data: Vec<Felt252> = get_felt_range(vm, request.data_start, request.data_end)?;
        self.events.push(OrderedEvent::new(order, keys, data));

        // Update events count.
        self.tx_execution_context.n_emitted_events += 1;
        Ok(SyscallResponse {
            gas: remaining_gas,
            body: None,
        })
    }
    #[allow(irrefutable_let_patterns)]
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

    //TODO remove allow irrefutable_let_patterns
    #[allow(irrefutable_let_patterns)]
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
}
