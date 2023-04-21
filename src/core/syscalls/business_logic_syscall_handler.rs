#![allow(dead_code)]

use std::collections::HashMap;

use super::{
    syscall_handler::SyscallHandler,
    syscall_info::get_syscall_size_from_name,
    syscall_request::{FromPtr, SyscallRequest},
    syscall_response::{CallContractResponse, ResponseBody},
};
use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{
                CallInfo, CallResult, CallType, OrderedEvent, OrderedL2ToL1Message,
                TransactionExecutionContext,
            },
        },
        fact_state::state::ExecutionResourcesManager,
        state::{
            contract_storage_state::ContractStorageState,
            state_api::{State, StateReader},
        },
    },
    core::errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError},
    definitions::{
        constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR, general_config::StarknetGeneralConfig,
    },
    hash_utils::calculate_contract_address,
    services::api::{
        contract_class_errors::ContractClassError,
        contract_classes::deprecated_contract_class::EntryPointType,
    },
    utils::{felt_to_hash, get_felt_range, Address, ClassHash},
};
use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::vm_core::VirtualMachine,
};
use felt::Felt252;
use lazy_static::lazy_static;
use num_traits::{One, Zero};

use super::syscall_response::SyscallResponse;
lazy_static! {
    /// Felt->syscall map that was extracted from new_syscalls.json (Cairo 1.0 syscalls)
    static ref SELECTOR_TO_SYSCALL: HashMap<Felt252, &'static str> =
        {
            let mut map: HashMap<Felt252, &'static str> = HashMap::with_capacity(9);

            map.insert(92376026794327011772951660_u128.into(), "library_call");
            map.insert(25500403217443378527601783667_u128.into(), "replace_class");
            map.insert(
                94901967946959054011942058057773508207_u128.into(),
                "get_execution_info",
            );
            map.insert(100890693370601760042082660_u128.into(), "storage_read");
            map.insert(20853273475220472486191784820_u128.into(), "call_contract");
            map.insert(
                433017908768303439907196859243777073_u128.into(),
                "send_message_to_l1",
            );
            map.insert(75202468540281_u128.into(), "deploy");
            map.insert(1280709301550335749748_u128.into(), "emit_event");
            map.insert(25828017502874050592466629733_u128.into(), "storage_write");

            map
        };
}

//TODO Remove allow dead_code after merging to 0.11
#[allow(dead_code)]
#[derive(Debug)]

pub struct BusinessLogicSyscallHandler<'a, T: State + StateReader> {
    pub(crate) events: Vec<OrderedEvent>,
    pub(crate) expected_syscall_ptr: Relocatable,
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) tx_execution_context: TransactionExecutionContext,
    pub(crate) l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub(crate) contract_address: Address,
    pub(crate) caller_address: Address,
    pub(crate) read_only_segments: Vec<(Relocatable, MaybeRelocatable)>,
    pub(crate) internal_calls: Vec<CallInfo>,
    pub(crate) general_config: StarknetGeneralConfig,
    pub(crate) entry_point: ExecutionEntryPoint,
    pub(crate) starknet_storage_state: ContractStorageState<'a, T>,
    pub(crate) support_reverted: bool,
    pub(crate) selector_to_syscall: &'a HashMap<Felt252, &'static str>,
}

// TODO: execution entry point may no be a parameter field, but there is no way to generate a default for now

impl<'a, T: Default + State + StateReader> BusinessLogicSyscallHandler<'a, T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_execution_context: TransactionExecutionContext,
        state: &'a mut T,
        resources_manager: ExecutionResourcesManager,
        caller_address: Address,
        contract_address: Address,
        general_config: StarknetGeneralConfig,
        syscall_ptr: Relocatable,
        entry_point: ExecutionEntryPoint,
    ) -> Self {
        let events = Vec::new();
        let read_only_segments = Vec::new();
        let l2_to_l1_messages = Vec::new();
        let starknet_storage_state = ContractStorageState::new(state, contract_address.clone());
        let internal_calls = Vec::new();

        BusinessLogicSyscallHandler {
            tx_execution_context,
            entry_point,
            events,
            read_only_segments,
            resources_manager,
            contract_address,
            caller_address,
            l2_to_l1_messages,
            general_config,
            starknet_storage_state,
            internal_calls,
            expected_syscall_ptr: syscall_ptr,
            support_reverted: false,
            selector_to_syscall: &SELECTOR_TO_SYSCALL,
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

    fn execute_constructor_entry_point(
        &mut self,
        contract_address: &Address,
        class_hash_bytes: ClassHash,
        constructor_calldata: Vec<Felt252>,
        remainig_gas: u64,
    ) -> Result<CallResult, StateError> {
        let contract_class = self
            .starknet_storage_state
            .state
            .get_contract_class(&class_hash_bytes)?;

        let constructor_entry_points = contract_class
            .entry_points_by_type
            .get(&EntryPointType::Constructor)
            .ok_or(ContractClassError::NoneEntryPointType)?;

        if constructor_entry_points.is_empty() {
            if !constructor_calldata.is_empty() {
                return Err(StateError::ConstructorCalldataEmpty());
            }

            let call_info = CallInfo::empty_constructor_call(
                contract_address.clone(),
                self.entry_point.contract_address.clone(),
                Some(class_hash_bytes),
            );
            self.internal_calls.push(call_info.clone());

            return Ok(call_info.result());
        }

        let call = ExecutionEntryPoint::new(
            contract_address.clone(),
            constructor_calldata,
            CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone(),
            self.entry_point.contract_address.clone(),
            EntryPointType::Constructor,
            Some(CallType::Call),
            None,
            remainig_gas,
        );

        // TODO: implement this function and logic once execution entry point is unlocked
        let call_info = call
            .execute_v2(
                self.starknet_storage_state.state,
                &mut self.general_config,
                self.support_reverted,
            )
            .map_err(|_| StateError::ExecutionEntryPoint())?;

        self.internal_calls.push(call_info.clone());

        Ok(call_info.result())
    }

    fn syscall_storage_write(&mut self, key: Felt252, value: Felt252) {
        self.starknet_storage_state.write(&key.to_le_bytes(), value)
    }
}

impl<'a, T> SyscallHandler for BusinessLogicSyscallHandler<'a, T>
where
    T: Default + State + StateReader,
{
    fn _storage_read(&mut self, key: [u8; 32]) -> Result<Felt252, StateError> {
        self.starknet_storage_state.read(&key).cloned()
    }

    fn storage_write(
        &mut self,
        _vm: &mut VirtualMachine,
        request: SyscallRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        let request = match request {
            SyscallRequest::StorageWrite(request) => request,
            _ => return Err(SyscallHandlerError::ExpectedStorageWriteSyscall),
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
            0,
        );

        self.call_contract_helper(vm, remaining_gas, execution_entry_point)
    }

    fn syscall_deploy(
        &mut self,
        vm: &VirtualMachine,
        syscall_request: SyscallRequest,
        remaining_gas: u64,
    ) -> Result<(Address, CallResult), SyscallHandlerError> {
        let request = match syscall_request {
            SyscallRequest::Deploy(request) => request,
            _ => return Err(SyscallHandlerError::IncorrectSyscall("Deploy".to_string())),
        };

        if !(request.deploy_from_zero.is_zero() || request.deploy_from_zero.is_one()) {
            return Err(SyscallHandlerError::DeployFromZero(
                request.deploy_from_zero,
            ));
        };

        let constructor_calldata =
            get_felt_range(vm, request.calldata_start, request.calldata_end)?;

        let class_hash = &request.class_hash;

        let deployer_address = if request.deploy_from_zero.is_zero() {
            self.entry_point.contract_address.clone()
        } else {
            Address(0.into())
        };

        let contract_address = Address(calculate_contract_address(
            &Address(request.salt),
            class_hash,
            &constructor_calldata,
            deployer_address,
        )?);

        // Initialize the contract.
        let class_hash_bytes: ClassHash = felt_to_hash(&request.class_hash);

        self.starknet_storage_state
            .state
            .deploy_contract(contract_address.clone(), class_hash_bytes)?;

        let result = self.execute_constructor_entry_point(
            &contract_address,
            class_hash_bytes,
            constructor_calldata,
            remaining_gas,
        )?;

        Ok((contract_address, result))
    }

    fn allocate_segment(
        &mut self,
        vm: &mut VirtualMachine,
        data: Vec<cairo_rs::types::relocatable::MaybeRelocatable>,
    ) -> Result<Relocatable, SyscallHandlerError> {
        let segment_start = vm.add_memory_segment();
        let segment_end = vm.write_arg(segment_start, &data)?;
        let sub = segment_end.sub(&segment_start.to_owned().into())?;
        let segment = (segment_start.to_owned(), sub);
        self.read_only_segments.push(segment);
        Ok(segment_start)
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
        vm: &mut VirtualMachine,
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
            0,
        );

        self.call_contract_helper(vm, remaining_gas, execution_entry_point)
    }
}
