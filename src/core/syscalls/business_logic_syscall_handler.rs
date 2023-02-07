use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Deref;
use std::rc::Rc;

use super::syscall_handler::SyscallHandler;
use super::syscall_request::*;
use crate::business_logic::execution::objects::*;
use crate::business_logic::fact_state::in_memory_state_reader::InMemoryStateReader;
use crate::business_logic::fact_state::state::ExecutionResourcesManager;
use crate::business_logic::state::cached_state::CachedState;
use crate::business_logic::state::contract_storage_state::ContractStorageState;
use crate::business_logic::state::state_api::{State, StateReader};
use crate::business_logic::state::state_api_objects::BlockInfo;
use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::definitions::general_config::StarknetGeneralConfig;
use crate::hash_utils::calculate_contract_address;
use crate::services::api::contract_class::EntryPointType;
use crate::starknet_storage::dict_storage::DictStorage;
use crate::utils::*;
use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use cairo_rs::vm::vm_core::VirtualMachine;
use felt::Felt;
use num_traits::{One, ToPrimitive, Zero};

//* -----------------------------------
//* BusinessLogicHandler implementation
//* -----------------------------------

pub struct BusinessLogicSyscallHandler<T: State + StateReader> {
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
    pub(crate) block_info: BlockInfo,
    pub(crate) state: T,
    pub(crate) starknet_storage_state: ContractStorageState<T>,
}

impl<T: State + StateReader + Clone> BusinessLogicSyscallHandler<T> {
    pub fn new(block_info: BlockInfo, contract_address: Address, state: T) -> Self {
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
        let general_config = StarknetGeneralConfig::default();
        let tx_info_ptr = None;
        let starknet_storage_state =
            ContractStorageState::new(state.clone(), contract_address.clone());

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
            block_info,
            state,
            starknet_storage_state,
        }
    }

    /// Increments the syscall count for a given `syscall_name` by 1.
    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
    }
}

impl<T: State + StateReader + Clone> SyscallHandler for BusinessLogicSyscallHandler<T> {
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
        let keys: Vec<Felt> = get_integer_range(vm, &request.keys, keys_len)?;
        let data: Vec<Felt> = get_integer_range(vm, &request.data, data_len)?;
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
        let segment_end = vm
            .write_arg(&segment_start, &data)
            .map_err(|_| SyscallHandlerError::SegmentationFault)?;
        let sub = segment_end
            .sub(&segment_start.to_owned().into())
            .map_err(|_| SyscallHandlerError::SegmentationFault)?;
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
            &request.constructor_calldata,
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

        let _contract_address = calculate_contract_address(
            &Address(request.contract_address_salt),
            class_hash,
            &constructor_calldata,
            deployer_address,
        )?;

        // Initialize the contract.
        let _class_hash_bytes = request.class_hash.to_bytes_be();

        todo!()
    }

    fn _call_contract(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Vec<u64>, SyscallHandlerError> {
        // Parse request and prepare the call.
        let request =
            match self._read_and_validate_syscall_request(syscall_name, vm, syscall_ptr)? {
                SyscallRequest::CallContract(request) => request,
                _ => return Err(SyscallHandlerError::ExpectedCallContract),
            };

        let calldata = get_integer_range(vm, &request.calldata, request.calldata_size)?;

        let mut code_address = None;
        let mut class_hash = None;

        match syscall_name {
            "call_contract" => {
                code_address = Some(request.contract_address);
                let contract_address = code_address;
                let caller_address = self.contract_address.clone();
                let entry_point_type = EntryPointType::External;
                let call_type = CallType::Call;
            }
            "delegate_call" => {
                code_address = Some(request.contract_address);
                let contract_address = self.contract_address.clone();
                let caller_address = self.caller_address.clone();
                let entry_point_type = EntryPointType::External;
                let call_type = CallType::Delegate;
            }
            "delegate_l1_handler" => {
                code_address = Some(request.contract_address);
                let contract_address = self.contract_address.clone();
                let caller_address = self.caller_address.clone();
                let entry_point_type = EntryPointType::L1Handler;
                let call_type = CallType::Delegate;
            }
            "library_call" => {
                class_hash = Some(request.class_hash.to_bytes_be());
                let contract_address = self.contract_address.clone();
                let caller_address = self.caller_address.clone();
                let entry_point_type = EntryPointType::External;
                let call_type = CallType::Delegate;
            }
            "library_call_l1_handler" => {
                class_hash = Some(request.class_hash.to_bytes_be());
                let contract_address = self.contract_address.clone();
                let caller_address = self.caller_address.clone();
                let entry_point_type = EntryPointType::L1Handler;
                let call_type = CallType::Delegate;
            }
            _ => {
                return Err(SyscallHandlerError::UnknownSyscall(
                    syscall_name.to_string(),
                ))
            }
        }

        // let call = self.execute_entry_point(
        //     call_type,
        //     class_hash,
        //     contract_address,
        //     code_address,
        //     request.selector,
        //     entry_point_type,
        //     calldata,
        //     caller_address,
        // )

        // return self.execute_entry_point(call=call)

        // TODO, remove this once used the commented code.
        todo!()
    }

    fn get_block_info(&self) -> &BlockInfo {
        &self.block_info
    }

    fn _get_caller_address(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        let request = if let SyscallRequest::GetCallerAddress(request) =
            self._read_and_validate_syscall_request("get_caller_address", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedGetCallerAddressRequest);
        };

        Ok(self.caller_address.clone())
    }
    fn _get_contract_address(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        if let SyscallRequest::GetContractAddress(request) =
            self._read_and_validate_syscall_request("get_contract_address", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedGetContractAddressRequest);
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

        let payload = get_integer_range(vm, &request.payload_ptr, request.payload_size)?;

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
            return Ok(ptr.get_relocatable()?);
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
        self._call_contract_and_write_response("library_call", vm, syscall_ptr);
        Ok(())
    }

    fn _storage_read(&mut self, address: Address) -> Result<Felt, SyscallHandlerError> {
        Ok(self
            .starknet_storage_state
            .read(&address.to_32_bytes()?)?
            .clone())
    }
    fn _storage_write(&mut self, address: Address, value: Felt) -> Result<(), SyscallHandlerError> {
        let _read = self.starknet_storage_state.read(&address.to_32_bytes()?)?;

        self.starknet_storage_state
            .write(&address.to_32_bytes()?, value);

        Ok(())
    }

    fn _read_and_validate_syscall_request(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        self.increment_syscall_count(syscall_name);
        self.read_syscall_request(syscall_name, vm, syscall_ptr)
    }
}

impl Default for BusinessLogicSyscallHandler<CachedState<InMemoryStateReader>> {
    fn default() -> Self {
        let cached_state = CachedState::new(
            BlockInfo::default(),
            InMemoryStateReader::new(DictStorage::new(), DictStorage::new()),
            None,
        );

        Self::new(BlockInfo::default(), Address(0.into()), cached_state)
    }
}

#[cfg(test)]
mod tests {
    use crate::business_logic::execution::objects::{
        OrderedEvent, OrderedL2ToL1Message, TransactionExecutionContext,
    };
    use crate::business_logic::state::state_api_objects::BlockInfo;
    use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
    use crate::core::syscalls::business_logic_syscall_handler::BusinessLogicSyscallHandler;
    use crate::core::syscalls::hint_code::*;
    use crate::core::syscalls::syscall_handler::*;
    use crate::utils::{get_integer, test_utils::*};
    use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
        BuiltinHintProcessor, HintProcessorData,
    };
    use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;
    use cairo_rs::relocatable;
    use cairo_rs::types::exec_scope::ExecutionScopes;
    use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
    use cairo_rs::vm::errors::hint_errors::HintError;
    use cairo_rs::vm::errors::memory_errors::MemoryError;
    use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
    use cairo_rs::vm::vm_core::VirtualMachine;
    use felt::Felt;
    use std::any::Any;
    use std::borrow::Cow;
    use std::collections::HashMap;

    #[test]
    fn run_alloc_hint_ap_is_not_empty() {
        let hint_code = "memory[ap] = segments.add()";
        let mut vm = vm!();
        //Add 3 segments to the memory
        add_segments!(vm, 3);
        vm.set_ap(6);
        //Insert something into ap
        let key = Relocatable::from((1, 6));
        vm.insert_value(&key, (1, 6)).unwrap();
        //ids and references are not needed for this test
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code),
            Err(HintError::Internal(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 6)),
                    MaybeRelocatable::from((1, 6)),
                    MaybeRelocatable::from((3, 0))
                )
            )))
        );
    }

    // tests that we are executing correctly our syscall hint processor.
    #[test]
    fn cannot_run_syscall_hints() {
        let hint_code = DEPLOY;
        let mut vm = vm!();
        assert_eq!(
            run_syscall_hint!(vm, HashMap::new(), hint_code),
            Err(HintError::UnknownHint("Hint not implemented".to_string()))
        );
    }

    fn deploy_from_zero_error() {
        let mut syscall = BusinessLogicSyscallHandler::default();
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

        assert_eq!(
            syscall._deploy(&vm, relocatable!(1, 0)),
            Err(SyscallHandlerError::DeployFromZero(4))
        )
    }

    #[test]
    fn can_allocate_segment() {
        let mut syscall_handler = BusinessLogicSyscallHandler::default();
        let mut vm = vm!();
        let data = vec![MaybeRelocatable::Int(7.into())];

        let segment_start = syscall_handler.allocate_segment(&mut vm, data).unwrap();
        let expected_value = vm
            .get_integer(&Relocatable::from((0, 0)))
            .unwrap()
            .into_owned();
        assert_eq!(Relocatable::from((0, 0)), segment_start);
        assert_eq!(expected_value, 7.into());
    }
    #[test]
    fn test_get_block_number() {
        let mut syscall = BusinessLogicSyscallHandler::default();
        let mut vm = vm!();

        add_segments!(vm, 2);
        vm.insert_value::<Felt>(&relocatable!(1, 0), 0.into())
            .unwrap();

        assert_eq!(
            syscall.get_block_number(&mut vm, relocatable!(1, 0)),
            Ok(()),
        );
        assert_eq!(
            vm.get_integer(&relocatable!(1, 1)).map(Cow::into_owned),
            Ok(0.into()),
        );
    }

    #[test]
    fn test_get_contract_address_ok() {
        let mut syscall = BusinessLogicSyscallHandler::default();
        let mut vm = vm!();

        add_segments!(vm, 2);

        vm.insert_value::<Felt>(&relocatable!(1, 0), 0.into())
            .unwrap();

        assert_eq!(
            syscall._get_contract_address(&vm, relocatable!(1, 0)),
            Ok(syscall.contract_address)
        )
    }
}
