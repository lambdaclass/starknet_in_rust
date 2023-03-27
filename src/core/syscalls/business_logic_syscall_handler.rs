use super::{
    syscall_handler::{SyscallHandler, SyscallHandlerPostRun},
    syscall_info::get_syscall_size_from_name,
    syscall_request::*,
};
use crate::{
    business_logic::{
        execution::{execution_entry_point::ExecutionEntryPoint, objects::*},
        fact_state::state::ExecutionResourcesManager,
        state::{
            contract_storage_state::ContractStorageState,
            state_api::{State, StateReader},
            state_api_objects::BlockInfo,
        },
        transaction::error::TransactionError,
    },
    core::errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError},
    definitions::general_config::StarknetGeneralConfig,
    hash_utils::calculate_contract_address,
    public::abi::CONSTRUCTOR_ENTRY_POINT_SELECTOR,
    services::api::{contract_class::EntryPointType, contract_class_errors::ContractClassError},
    utils::*,
};
use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{runners::cairo_runner::ExecutionResources, vm_core::VirtualMachine},
};
use felt::Felt252;
use num_traits::{One, ToPrimitive, Zero};
use std::borrow::{Borrow, BorrowMut};

//* -----------------------------------
//* BusinessLogicHandler implementation
//* -----------------------------------

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

    pub fn default_with(state: &'a mut T) -> Self {
        BusinessLogicSyscallHandler::new_for_testing(
            BlockInfo::default(),
            Default::default(),
            state,
        )
    }

    /// Increments the syscall count for a given `syscall_name` by 1.
    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }

    pub fn new_for_testing(
        block_info: BlockInfo,
        _contract_address: Address,
        state: &'a mut T,
    ) -> Self {
        let syscalls = Vec::from([
            "emit_event".to_string(),
            "deploy".to_string(),
            "get_tx_info".to_string(),
            "send_message_to_l1".to_string(),
            "library_call".to_string(),
            "get_caller_address".to_string(),
            "get_contract_address".to_string(),
            "get_sequencer_address".to_string(),
            "get_block_timestamp".to_string(),
        ]);
        let events = Vec::new();
        let tx_execution_context = TransactionExecutionContext {
            ..Default::default()
        };
        let read_only_segments = Vec::new();
        let resources_manager = ExecutionResourcesManager::new(
            syscalls,
            ExecutionResources {
                ..Default::default()
            },
        );
        let contract_address = Address(1.into());
        let caller_address = Address(0.into());
        let l2_to_l1_messages = Vec::new();
        let mut general_config = StarknetGeneralConfig::default();
        general_config.block_info = block_info;
        let tx_info_ptr = None;
        let starknet_storage_state = ContractStorageState::new(state, contract_address.clone());

        let internal_calls = Vec::new();
        let expected_syscall_ptr = Relocatable::from((0, 0));

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
        }
    }

    /// Validates that there were no out of bounds writes to read-only segments and marks
    /// them as accessed.
    pub(crate) fn validate_read_only_segments(
        &self,
        runner: &mut VirtualMachine,
    ) -> Result<(), TransactionError> {
        for (segment_ptr, segment_size) in self.read_only_segments.clone() {
            let used_size = runner
                .get_segment_used_size(segment_ptr.segment_index as usize)
                .ok_or(TransactionError::InvalidSegmentSize)?;

            let seg_size = match segment_size {
                MaybeRelocatable::Int(size) => size,
                _ => return Err(TransactionError::NotAnInt),
            };

            if seg_size != used_size.into() {
                return Err(TransactionError::OutOfBound);
            }
            runner.mark_address_range_as_accessed(segment_ptr, used_size)?;
        }
        Ok(())
    }

    fn execute_constructor_entry_point(
        &mut self,
        contract_address: &Address,
        class_hash_bytes: ClassHash,
        constructor_calldata: Vec<Felt252>,
    ) -> Result<(), StateError> {
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
                self.caller_address.clone(),
                Some(class_hash_bytes),
            );
            self.internal_calls.push(call_info);

            return Ok(());
        }

        let call = ExecutionEntryPoint::new(
            contract_address.clone(),
            constructor_calldata,
            CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone(),
            self.contract_address.clone(),
            EntryPointType::Constructor,
            Some(CallType::Call),
            None,
        );

        let _call_info = call
            .execute(
                self.starknet_storage_state.state,
                &self.general_config,
                &mut self.resources_manager,
                &self.tx_execution_context,
            )
            .map_err(|_| StateError::ExecutionEntryPoint())?;
        Ok(())
    }
}

impl<'a, T> Borrow<T> for BusinessLogicSyscallHandler<'a, T>
where
    T: State + StateReader,
{
    fn borrow(&self) -> &T {
        self.starknet_storage_state.state
    }
}

impl<'a, T> BorrowMut<T> for BusinessLogicSyscallHandler<'a, T>
where
    T: State + StateReader,
{
    fn borrow_mut(&mut self) -> &mut T {
        self.starknet_storage_state.state
    }
}

impl<'a, T> SyscallHandler for BusinessLogicSyscallHandler<'a, T>
where
    T: Default + State + StateReader,
{
    fn emit_event(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let request = match self._read_and_validate_syscall_request("emit_event", vm, syscall_ptr) {
            Ok(SyscallRequest::EmitEvent(emit_event_struct)) => emit_event_struct,
            _ => return Err(SyscallHandlerError::InvalidSyscallReadRequest),
        };

        let keys_len = request.keys_len;
        let data_len = request.data_len;
        let order = self.tx_execution_context.n_emitted_events;
        let keys: Vec<Felt252> = get_integer_range(vm, request.keys, keys_len)?;
        let data: Vec<Felt252> = get_integer_range(vm, request.data, data_len)?;
        self.events.push(OrderedEvent::new(order, keys, data));

        // Update events count.
        self.tx_execution_context.n_emitted_events += 1;
        Ok(())
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

    fn _deploy(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        let request = if let SyscallRequest::Deploy(request) =
            self._read_and_validate_syscall_request("deploy", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedDeployRequestStruct);
        };

        if !(request.deploy_from_zero.is_zero() || request.deploy_from_zero.is_one()) {
            return Err(SyscallHandlerError::DeployFromZero(
                request.deploy_from_zero,
            ));
        };

        let constructor_calldata = get_integer_range(
            vm,
            request.constructor_calldata,
            request
                .constructor_calldata_size
                .to_usize()
                .ok_or(SyscallHandlerError::FeltToUsizeFail)?,
        )?;

        let class_hash = &request.class_hash;

        let deployer_address = if request.deploy_from_zero.is_zero() {
            self.contract_address.clone()
        } else {
            Address(0.into())
        };

        let deploy_contract_address = Address(calculate_contract_address(
            &Address(request.contract_address_salt),
            class_hash,
            &constructor_calldata,
            deployer_address,
        )?);

        // Initialize the contract.
        let class_hash_bytes: ClassHash = felt_to_hash(&request.class_hash);

        self.starknet_storage_state
            .state
            .deploy_contract(deploy_contract_address.clone(), class_hash_bytes)?;
        self.execute_constructor_entry_point(
            &deploy_contract_address,
            class_hash_bytes,
            constructor_calldata,
        )?;
        Ok(deploy_contract_address)
    }

    fn _call_contract(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Vec<Felt252>, SyscallHandlerError> {
        let request = self._read_and_validate_syscall_request(syscall_name, vm, syscall_ptr)?;

        let entry_point_type;
        let function_selector;
        let class_hash;
        let contract_address;
        let caller_address;
        let call_type;
        let call_data;

        // TODO: What about `delegate_call`, `delegate_l1_handler`?
        //   The call to `self._read_and_validate_syscall_request()` will always fail in those
        //   cases.
        match request {
            SyscallRequest::LibraryCall(request) => {
                entry_point_type = match syscall_name {
                    "library_call" => EntryPointType::External,
                    "library_call_l1_handler" => EntryPointType::L1Handler,
                    _ => return Err(SyscallHandlerError::NotImplemented),
                };
                function_selector = request.function_selector;
                class_hash = Some(felt_to_hash(&request.class_hash));
                contract_address = self.contract_address.clone();
                caller_address = self.caller_address.clone();
                call_type = CallType::Delegate;
                call_data = get_integer_range(vm, request.calldata, request.calldata_size)?;
            }
            SyscallRequest::CallContract(request) => {
                entry_point_type = match syscall_name {
                    "call_contract" => EntryPointType::External,
                    _ => return Err(SyscallHandlerError::NotImplemented),
                };
                function_selector = request.function_selector;
                class_hash = None;
                contract_address = request.contract_address;
                caller_address = self.contract_address.clone();
                call_type = CallType::Call;
                call_data = get_integer_range(vm, request.calldata, request.calldata_size)?;
            }
            _ => return Err(SyscallHandlerError::NotImplemented),
        }

        let entry_point = ExecutionEntryPoint::new(
            contract_address,
            call_data,
            function_selector,
            caller_address,
            entry_point_type,
            Some(call_type),
            class_hash,
        );

        entry_point
            .execute(
                self.starknet_storage_state.state,
                &self.general_config,
                &mut self.resources_manager,
                &self.tx_execution_context,
            )
            .map(|x| {
                let retdata = x.retdata.clone();
                self.internal_calls.push(x);

                retdata
            })
            .map_err(|e| SyscallHandlerError::ExecutionError(e.to_string()))
    }

    fn get_block_info(&self) -> &BlockInfo {
        &self.general_config.block_info
    }

    fn _get_caller_address(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        match self._read_and_validate_syscall_request("get_caller_address", vm, syscall_ptr)? {
            SyscallRequest::GetCallerAddress(_) => {}
            _ => return Err(SyscallHandlerError::ExpectedGetCallerAddressRequest),
        }

        Ok(self.caller_address.clone())
    }

    fn _get_contract_address(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        match self._read_and_validate_syscall_request("get_contract_address", vm, syscall_ptr)? {
            SyscallRequest::GetContractAddress(_) => {}
            _ => return Err(SyscallHandlerError::ExpectedGetContractAddressRequest),
        };

        Ok(self.contract_address.clone())
    }

    fn send_message_to_l1(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let request = if let SyscallRequest::SendMessageToL1(request) =
            self._read_and_validate_syscall_request("send_message_to_l1", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedSendMessageToL1);
        };

        let payload = get_integer_range(vm, request.payload_ptr, request.payload_size)?;

        self.l2_to_l1_messages.push(OrderedL2ToL1Message::new(
            self.tx_execution_context.n_sent_messages,
            request.to_address,
            payload,
        ));

        // Update messages count.
        self.tx_execution_context.n_sent_messages += 1;
        Ok(())
    }

    fn _get_tx_info_ptr(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> Result<Relocatable, SyscallHandlerError> {
        if let Some(ptr) = &self.tx_info_ptr {
            return Ok(ptr.try_into()?);
        }
        let tx = self.tx_execution_context.clone();

        let signature_data: Vec<MaybeRelocatable> =
            tx.signature.iter().map(|num| num.into()).collect();
        let signature = self.allocate_segment(vm, signature_data)?;

        let tx_info = TxInfoStruct::new(
            tx,
            signature,
            self.general_config.starknet_os_config.chain_id,
        );

        let tx_info_ptr_temp = self.allocate_segment(vm, tx_info.to_vec())?;

        self.tx_info_ptr = Some(tx_info_ptr_temp.into());

        Ok(tx_info_ptr_temp)
    }

    fn library_call(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        self._call_contract_and_write_response("library_call", vm, syscall_ptr)
    }

    fn library_call_l1_handler(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        self._call_contract_and_write_response("library_call_l1_handler", vm, syscall_ptr)
    }

    fn call_contract(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        self._call_contract_and_write_response("call_contract", vm, syscall_ptr)
    }

    fn _storage_read(&mut self, address: Address) -> Result<Felt252, SyscallHandlerError> {
        Ok(self
            .starknet_storage_state
            .read(&felt_to_hash(&address.0))
            .cloned()?)
    }

    fn _storage_write(
        &mut self,
        address: Address,
        value: Felt252,
    ) -> Result<(), SyscallHandlerError> {
        self.starknet_storage_state
            .write(&felt_to_hash(&address.0), value);

        Ok(())
    }

    fn _read_and_validate_syscall_request(
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

impl<'a, T> SyscallHandlerPostRun for BusinessLogicSyscallHandler<'a, T>
where
    T: Default + State + StateReader,
{
    fn post_run(
        &self,
        runner: &mut VirtualMachine,
        syscall_stop_ptr: Relocatable,
    ) -> Result<(), TransactionError> {
        let expected_stop_ptr = self.expected_syscall_ptr;
        if syscall_stop_ptr != expected_stop_ptr {
            return Err(TransactionError::InvalidStopPointer(
                expected_stop_ptr,
                syscall_stop_ptr,
            ));
        }
        self.validate_read_only_segments(runner)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        business_logic::{
            fact_state::in_memory_state_reader::InMemoryStateReader,
            state::cached_state::CachedState,
        },
        core::{
            errors::syscall_handler_errors::SyscallHandlerError,
            syscalls::syscall_handler::SyscallHandler,
        },
        utils::{test_utils::*, Address},
    };
    use cairo_rs::{
        hint_processor::{
            builtin_hint_processor::builtin_hint_processor_definition::{
                BuiltinHintProcessor, HintProcessorData,
            },
            hint_processor_definition::HintProcessor,
        },
        relocatable,
        types::{
            exec_scope::ExecutionScopes,
            relocatable::{MaybeRelocatable, Relocatable},
        },
        vm::{errors::memory_errors::MemoryError, vm_core::VirtualMachine},
    };
    use felt::Felt252;
    use num_traits::Zero;
    use std::{any::Any, borrow::Cow, collections::HashMap};

    type BusinessLogicSyscallHandler<'a> =
        super::BusinessLogicSyscallHandler<'a, CachedState<InMemoryStateReader>>;

    #[test]
    fn run_alloc_hint_ap_is_not_empty() {
        let hint_code = "memory[ap] = segments.add()";
        let mut vm = vm!();
        //Add 3 segments to the memory
        add_segments!(vm, 3);
        vm.set_ap(6);
        //Insert something into ap
        let key = Relocatable::from((1, 6));
        vm.insert_value(key, (1, 6)).unwrap();
        //ids and references are not needed for this test
        assert_matches!(
            run_hint!(vm, HashMap::new(), hint_code),
            Err(e) if e.to_string().contains(&MemoryError::InconsistentMemory(Relocatable::from((1, 6)),MaybeRelocatable::from((1, 6)),MaybeRelocatable::from((3, 0))).to_string())
        );
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn deploy_from_zero_error() {
        let mut state = CachedState::<InMemoryStateReader>::default();
        let mut syscall = BusinessLogicSyscallHandler::default_with(&mut state);
        let mut vm = vm!();

        add_segments!(vm, 2);

        memory_insert!(
            vm,
            [
                ((1, 0), 0),
                ((1, 1), 1),
                ((1, 2), 2),
                ((1, 3), 3),
                ((1, 4), (1, 20)),
                ((1, 5), 4)
            ]
        );

        assert_matches!(
            syscall._deploy(&vm, relocatable!(1, 0)),
            Err(SyscallHandlerError::DeployFromZero(4))
        )
    }

    #[test]
    fn can_allocate_segment() {
        let mut state = CachedState::<InMemoryStateReader>::default();
        let mut syscall_handler = BusinessLogicSyscallHandler::default_with(&mut state);
        let mut vm = vm!();
        let data = vec![MaybeRelocatable::Int(7.into())];

        let segment_start = syscall_handler.allocate_segment(&mut vm, data).unwrap();
        let expected_value = vm
            .get_integer(Relocatable::from((0, 0)))
            .unwrap()
            .into_owned();
        assert_eq!(Relocatable::from((0, 0)), segment_start);
        assert_eq!(expected_value, 7.into());
    }

    #[test]
    fn test_get_block_number() {
        let mut state = CachedState::<InMemoryStateReader>::default();
        let mut syscall = BusinessLogicSyscallHandler::default_with(&mut state);
        let mut vm = vm!();

        add_segments!(vm, 2);
        vm.insert_value::<Felt252>(relocatable!(1, 0), 0.into())
            .unwrap();

        assert_matches!(
            syscall.get_block_number(&mut vm, relocatable!(1, 0)),
            Ok(())
        );
        assert_matches!(
            vm.get_integer(relocatable!(1, 1)).map(Cow::into_owned),
            Ok(value) if value == 0.into()
        );
    }

    #[test]
    fn test_get_contract_address_ok() {
        let mut state = CachedState::<InMemoryStateReader>::default();
        let mut syscall = BusinessLogicSyscallHandler::default_with(&mut state);
        let mut vm = vm!();

        add_segments!(vm, 2);

        vm.insert_value::<Felt252>(relocatable!(1, 0), 0.into())
            .unwrap();

        assert_matches!(
            syscall._get_contract_address(&vm, relocatable!(1, 0)),
            Ok(contract_address) if contract_address == syscall.contract_address
        )
    }

    #[test]
    fn test_storage_read_empty() {
        let mut state = CachedState::<InMemoryStateReader>::default();
        let mut syscall_handler = BusinessLogicSyscallHandler::default_with(&mut state);

        assert_matches!(
            syscall_handler._storage_read(Address(Felt252::zero())),
            Ok(value) if value == Felt252::zero()
        );
    }
}
