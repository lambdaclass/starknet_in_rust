use super::{syscall_handler::SyscallHandler, syscall_request::SyscallRequest};
use crate::{
    business_logic::{
        execution::objects::{CallInfo, TransactionExecutionInfo},
        state::state_api_objects::BlockInfo,
    },
    core::errors::syscall_handler_errors::SyscallHandlerError,
    services::api::contract_class::EntryPointType,
    utils::Address,
};
use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::vm_core::VirtualMachine,
};
use felt::Felt252;
use std::collections::{HashMap, VecDeque};

#[derive(Debug)]
pub(crate) struct OsSingleStarknetStorage;

impl OsSingleStarknetStorage {
    /// Writes the given value in the given key in ongoing_storage_changes and returns the
    /// previous value. This value is needed to create the DictAccess while executing the
    /// corresponding storage_write system call.
    fn write(&self, _key: u64, _value: u64) -> u64 {
        // TO BE IMPLEMENTED
        todo!()
    }
}

#[derive(Debug, Default)]
pub(crate) struct OsSyscallHandler {
    tx_execution_info_iterator: VecDeque<TransactionExecutionInfo>,
    call_iterator: VecDeque<CallInfo>,

    /// A stack that keeps track of the state of the calls being executed now.
    /// The last item is the state of the current call; the one before it, is the
    /// state of the caller (the call the called the current call); and so on.
    call_stack: VecDeque<CallInfo>,
    /// An iterator over contract addresses that were deployed during that call.
    deployed_contracts_iterator: VecDeque<Address>, // felt
    /// An iterator to the retdata of its internal calls.
    retdata_iterator: VecDeque<VecDeque<Felt252>>, //VEC<felt>
    /// An iterator to the read_values array which is consumed when the transaction
    /// code is executed.
    execute_code_read_iterator: VecDeque<Felt252>, //felt
    /// StarkNet storage members.
    starknet_storage_by_address: HashMap<Felt252, OsSingleStarknetStorage>,
    /// A pointer to the Cairo TxInfo struct.
    /// This pointer needs to match the TxInfo pointer that is going to be used during the system
    /// call validation by the StarkNet OS.
    /// Set during enter_tx.
    pub(crate) tx_info_ptr: Option<Relocatable>,
    /// The TransactionExecutionInfo for the transaction currently being executed.
    tx_execution_info: Option<TransactionExecutionInfo>,
    block_info: BlockInfo,
}

impl SyscallHandler for OsSyscallHandler {
    fn emit_event(
        &mut self,
        _vm: &VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        todo!()
    }

    fn library_call(
        &mut self,
        _vm: &mut VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        todo!()
    }

    fn library_call_l1_handler(
        &mut self,
        _vm: &mut VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        todo!()
    }

    fn call_contract(
        &mut self,
        _vm: &mut VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        todo!()
    }

    fn send_message_to_l1(
        &mut self,
        _vm: &VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        Ok(())
    }

    fn _get_tx_info_ptr(
        &mut self,
        _vm: &mut VirtualMachine,
    ) -> Result<Relocatable, SyscallHandlerError> {
        Ok(*self
            .tx_info_ptr
            .as_ref()
            .ok_or(SyscallHandlerError::TxInfoPtrIsNone)?)
    }

    fn _deploy(
        &mut self,
        _vm: &VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        let constructor_retdata = self
            .retdata_iterator
            .pop_front()
            .ok_or(SyscallHandlerError::IteratorEmpty)?;
        match constructor_retdata.len() {
            0 => (),
            _ => Err(SyscallHandlerError::UnexpectedConstructorRetdata)?,
        }
        self.deployed_contracts_iterator
            .pop_front()
            .ok_or(SyscallHandlerError::IteratorEmpty)
    }

    /// Returns the system call request written in the syscall segment, starting at syscall_ptr.
    /// Does not perform validations on the request, since it was validated in the BL.
    fn _read_and_validate_syscall_request(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        self.read_syscall_request(syscall_name, vm, syscall_ptr)
    }

    fn _call_contract(
        &mut self,
        _syscall_name: &str,
        _vm: &VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Result<Vec<Felt252>, SyscallHandlerError> {
        Ok(self
            .retdata_iterator
            .pop_front()
            .ok_or(SyscallHandlerError::IteratorEmpty)?
            .into())
    }

    fn _get_caller_address(
        &mut self,
        _vm: &VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        match self.call_stack.back() {
            None => Err(SyscallHandlerError::ListIsEmpty)?,
            Some(call_info) => Ok(call_info.caller_address.clone()),
        }
    }

    fn _get_contract_address(
        &mut self,
        _vm: &VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        match self.call_stack.front() {
            None => Err(SyscallHandlerError::ListIsEmpty)?,
            Some(call_info) => Ok(call_info.contract_address.clone()),
        }
    }

    fn _storage_read(&mut self, _address: Address) -> Result<Felt252, SyscallHandlerError> {
        self.execute_code_read_iterator
            .pop_front()
            .ok_or(SyscallHandlerError::IteratorEmpty)
    }

    /// Advance execute_code_read_iterators since the previous storage value is written
    /// in each write operation. See BusinessLogicSysCallHandler._storage_write().
    fn _storage_write(
        &mut self,
        _address: Address,
        _value: Felt252,
    ) -> Result<(), SyscallHandlerError> {
        self.execute_code_read_iterator.pop_front();
        Ok(())
    }

    /// Allocates and returns a new temporary segment.
    fn allocate_segment(
        &mut self,
        vm: &mut VirtualMachine,
        data: Vec<MaybeRelocatable>,
    ) -> Result<Relocatable, SyscallHandlerError> {
        let segment_start = vm.add_temporary_segment();

        vm.write_arg(segment_start, &data)?;
        Ok(segment_start)
    }

    fn get_block_info(&self) -> &BlockInfo {
        &self.block_info
    }
}

impl OsSyscallHandler {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        tx_execution_info_iterator: VecDeque<TransactionExecutionInfo>,
        call_iterator: VecDeque<CallInfo>,
        call_stack: VecDeque<CallInfo>,
        deployed_contracts_iterator: VecDeque<Address>,
        retdata_iterator: VecDeque<VecDeque<Felt252>>,
        execute_code_read_iterator: VecDeque<Felt252>,
        starknet_storage_by_address: HashMap<Felt252, OsSingleStarknetStorage>,
        tx_info_ptr: Option<Relocatable>,
        tx_execution_info: Option<TransactionExecutionInfo>,
        block_info: BlockInfo,
    ) -> Self {
        Self {
            tx_execution_info_iterator,
            call_iterator,
            call_stack,
            deployed_contracts_iterator,
            retdata_iterator,
            execute_code_read_iterator,
            starknet_storage_by_address,
            tx_info_ptr,
            tx_execution_info,
            block_info,
        }
    }

    pub(crate) fn default() -> Self {
        Self::new(
            VecDeque::new(),
            VecDeque::new(),
            VecDeque::new(),
            VecDeque::new(),
            VecDeque::new(),
            VecDeque::new(),
            HashMap::new(),
            None,
            None,
            BlockInfo::default(),
        )
    }

    /// Called when starting the execution of a transaction.
    /// 'tx_info_ptr' is a pointer to the TxInfo struct corresponding to said transaction.
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn start_tx(&mut self, tx_info_ptr: Relocatable) -> Result<(), SyscallHandlerError> {
        if self.tx_info_ptr.is_some() {
            return Err(SyscallHandlerError::ShouldBeNone(String::from(
                "tx_info_ptr",
            )));
        }

        self.tx_info_ptr = Some(tx_info_ptr);

        if self.tx_execution_info.is_some() {
            return Err(SyscallHandlerError::ShouldBeNone(String::from(
                "tx_execution_info",
            )));
        }

        self.tx_execution_info = self.tx_execution_info_iterator.pop_front();
        // TO BE IMPLEMENTED
        // self.call_iterator = self.tx_execution_info.gen_call_iterator(); TO BE IMPLEMENTED
        Ok(())
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn skip_tx(&mut self) -> Option<TransactionExecutionInfo> {
        self.tx_execution_info_iterator.pop_front()
    }

    fn assert_iterators_exhausted(&self) -> Result<(), SyscallHandlerError> {
        if self.deployed_contracts_iterator.front().is_some() {
            return Err(SyscallHandlerError::IteratorNotEmpty);
        };
        if self.retdata_iterator.front().is_some() {
            return Err(SyscallHandlerError::IteratorNotEmpty);
        };
        if self.execute_code_read_iterator.front().is_some() {
            return Err(SyscallHandlerError::IteratorNotEmpty);
        };
        Ok(())
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn exit_call(&mut self) -> Result<Option<CallInfo>, SyscallHandlerError> {
        self.assert_iterators_exhausted()?;
        Ok(self.call_stack.pop_front())
    }

    /// Called after the execution of the current transaction complete.
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn end_tx(&mut self) -> Result<(), SyscallHandlerError> {
        if self.execute_code_read_iterator.front().is_some() {
            return Err(SyscallHandlerError::IteratorNotEmpty);
        };

        if self.tx_info_ptr.is_some() {
            return Err(SyscallHandlerError::ShouldBeNone(String::from(
                "tx_info_ptr",
            )));
        };
        self.tx_info_ptr = None;

        if self.tx_execution_info.is_some() {
            return Err(SyscallHandlerError::ShouldBeNone(String::from(
                "tx_execution_info",
            )));
        }
        self.tx_execution_info = None;
        Ok(())
    }

    // TODO TEST
    // This cannot be tested until OsSingleStarknetStorage::write/3 is implemented.

    /// Updates the cached storage and returns the storage value before
    /// the write operation.
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn execute_syscall_storage_write(
        &self,
        contract_address: &Address,
        key: u64,
        value: u64,
    ) -> Result<u64, SyscallHandlerError> {
        Ok(self
            .starknet_storage_by_address
            .get(&contract_address.0)
            .ok_or(SyscallHandlerError::KeyNotFound)?
            .write(key, value))
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn enter_call(&mut self) -> Result<(), SyscallHandlerError> {
        self.assert_iterators_exhausted()?;

        let call_info = self
            .call_iterator
            .pop_front()
            .ok_or(SyscallHandlerError::IteratorEmpty)?;
        self.call_stack.push_back(call_info.clone());

        self.deployed_contracts_iterator = call_info
            .internal_calls
            .iter()
            .filter(|call_info_internal| {
                call_info_internal.entry_point_type == Some(EntryPointType::Constructor)
            })
            .map(|call_info_internal| call_info_internal.contract_address.clone())
            .collect::<VecDeque<Address>>();

        self.retdata_iterator = call_info
            .internal_calls
            .into_iter()
            .map(|call_info_internal| call_info_internal.retdata.into())
            .collect::<VecDeque<VecDeque<Felt252>>>();

        self.execute_code_read_iterator = call_info.storage_read_values.into();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CallInfo, OsSyscallHandler};
    use crate::{
        business_logic::execution::objects::TransactionExecutionInfo,
        core::{
            errors::syscall_handler_errors::SyscallHandlerError,
            syscalls::syscall_handler::SyscallHandler,
        },
        utils::{get_integer, get_relocatable, test_utils::*, Address},
    };
    use cairo_rs::{
        types::relocatable::{MaybeRelocatable, Relocatable},
        vm::{
            errors::memory_errors::MemoryError, runners::cairo_runner::ExecutionResources,
            vm_core::VirtualMachine,
        },
    };
    use felt::Felt252;
    use std::collections::{HashMap, HashSet, VecDeque};

    #[test]
    fn get_contract_address() {
        let mut call_stack = VecDeque::new();
        let call_info = CallInfo {
            contract_address: Address(5.into()),
            caller_address: Address(1.into()),
            code_address: None,
            internal_calls: Vec::new(),
            entry_point_type: None,
            storage_read_values: Vec::new(),
            retdata: Vec::new(),
            entry_point_selector: None,
            l2_to_l1_messages: Vec::new(),
            accessed_storage_keys: HashSet::new(),
            calldata: Vec::new(),
            execution_resources: ExecutionResources {
                n_steps: 0,
                n_memory_holes: 0,
                builtin_instance_counter: HashMap::new(),
            },
            events: Vec::new(),
            call_type: None,
            class_hash: Some([0; 32]),
        };
        call_stack.push_back(call_info);

        let mut handler = OsSyscallHandler {
            call_stack,
            tx_info_ptr: Some(Relocatable {
                segment_index: 0,
                offset: 0,
            }),
            ..Default::default()
        };

        let vm = vm!();
        let reloc = Relocatable {
            segment_index: 0,
            offset: 0,
        };
        let get_contract_address = handler._get_contract_address(&vm, reloc);
        assert_matches!(get_contract_address, Ok(contract_address) if contract_address == Address(5.into()))
    }

    #[test]
    fn get_contract_address_err() {
        let mut handler = OsSyscallHandler {
            tx_info_ptr: Some(Relocatable {
                segment_index: 0,
                offset: 0,
            }),
            ..Default::default()
        };

        let vm = vm!();
        let reloc = Relocatable {
            segment_index: 0,
            offset: 0,
        };
        let get_contract_address = handler._get_contract_address(&vm, reloc).unwrap_err();
        assert_matches!(get_contract_address, SyscallHandlerError::ListIsEmpty)
    }

    #[test]
    fn end_tx_err_execute_code_read_iterator() {
        let mut execute_code_read_iterator = VecDeque::new();
        execute_code_read_iterator.push_back(12.into());
        let mut handler = OsSyscallHandler {
            execute_code_read_iterator,
            ..Default::default()
        };

        assert_matches!(handler.end_tx(), Err(SyscallHandlerError::IteratorNotEmpty))
    }

    #[test]
    fn end_tx_err_tx_info_ptr() {
        let tx_info_ptr = Some(Relocatable {
            segment_index: 0,
            offset: 0,
        });

        let mut handler = OsSyscallHandler {
            tx_info_ptr,
            ..Default::default()
        };

        assert_matches!(
            handler.end_tx(),
            Err(SyscallHandlerError::ShouldBeNone(err)) if err == *"tx_info_ptr"
        )
    }

    #[test]
    fn end_tx_err_tx_execution_info() {
        let mut handler = OsSyscallHandler {
            tx_execution_info: Some(TransactionExecutionInfo {
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_matches!(
            handler.end_tx(),
            Err(SyscallHandlerError::ShouldBeNone(err)) if err == *"tx_execution_info"
        )
    }

    #[test]
    fn end_tx() {
        let mut handler = OsSyscallHandler::default();

        assert_matches!(handler.end_tx(), Ok(()))
    }

    #[test]
    fn start_tx_err_tx_info_ptr() {
        let tx_info_ptr = Some(Relocatable {
            segment_index: 0,
            offset: 0,
        });

        let mut handler = OsSyscallHandler {
            tx_info_ptr,
            ..Default::default()
        };

        let reloc = Relocatable {
            segment_index: 1,
            offset: 1,
        };

        assert_matches!(
            handler.start_tx(reloc),
            Err(SyscallHandlerError::ShouldBeNone(err)) if err == *"tx_info_ptr"
        )
    }

    #[test]
    fn start_tx_err_tx_execution_info() {
        let tx_execution_info = Some(TransactionExecutionInfo {
            ..Default::default()
        });

        let mut handler = OsSyscallHandler {
            tx_execution_info,
            ..Default::default()
        };

        let reloc = Relocatable {
            segment_index: 1,
            offset: 1,
        };

        assert_matches!(
            handler.start_tx(reloc),
            Err(SyscallHandlerError::ShouldBeNone(err)) if err == *"tx_execution_info"
        )
    }

    #[test]
    fn start_tx() {
        let mut handler = OsSyscallHandler::default();

        let reloc = Relocatable {
            segment_index: 0,
            offset: 0,
        };

        assert_matches!(handler.start_tx(reloc), Ok(()))
    }

    #[test]
    fn skip_tx() {
        let mut tx_execution_info_iterator = VecDeque::new();
        tx_execution_info_iterator.push_back(TransactionExecutionInfo {
            ..Default::default()
        });
        let mut handler = OsSyscallHandler {
            tx_execution_info_iterator,
            ..Default::default()
        };

        assert_eq!(
            handler.skip_tx(),
            Some(TransactionExecutionInfo {
                ..Default::default()
            })
        );
        assert_eq!(handler.skip_tx(), None)
    }

    #[test]
    fn get_tx_info_ptr_reloc() {
        let mut handler = OsSyscallHandler {
            tx_info_ptr: Some(Relocatable {
                segment_index: 0,
                offset: 0,
            }),
            ..Default::default()
        };

        let mut vm = vm!();
        assert_matches!(
            handler._get_tx_info_ptr(&mut vm),
            Ok(Relocatable {
                segment_index: 0,
                offset: 0,
            })
        )
    }

    #[test]
    fn get_tx_info_ptr_none() {
        let mut handler = OsSyscallHandler::default();

        let mut vm = vm!();

        assert_matches!(
            handler._get_tx_info_ptr(&mut vm),
            Err(SyscallHandlerError::TxInfoPtrIsNone)
        )
    }

    #[test]
    fn call_contract() {
        let mut retdata_iterator = VecDeque::new();
        retdata_iterator.push_back(VecDeque::new());
        retdata_iterator.push_back(VecDeque::new());
        let mut handler = OsSyscallHandler {
            retdata_iterator,
            ..Default::default()
        };

        let vm = vm!();
        let ptr = Relocatable {
            segment_index: 0,
            offset: 0,
        };

        assert_matches!(handler._call_contract("", &vm, ptr), Ok(ret_data) if ret_data == Vec::new());
        assert_matches!(handler._call_contract("", &vm, ptr), Ok(ret_data) if ret_data == Vec::new());
        assert_matches!(
            handler._call_contract("", &vm, ptr),
            Err(SyscallHandlerError::IteratorEmpty)
        )
    }

    #[test]
    fn storage_deploy() {
        let mut retdata_iterator = VecDeque::new();
        retdata_iterator.push_back(VecDeque::new());
        let mut deployed_contracts_iterator = VecDeque::new();
        deployed_contracts_iterator.push_back(Address(12.into()));
        let mut handler = OsSyscallHandler {
            deployed_contracts_iterator,
            retdata_iterator,
            ..Default::default()
        };

        let vm = vm!();
        let ptr = Relocatable {
            segment_index: 0,
            offset: 0,
        };

        assert_matches!(handler._deploy(&vm, ptr), Ok(deploy_address) if deploy_address == Address(12.into()));
    }

    #[test]
    fn storage_deploy_err_retdata_iterator_multiple() {
        let mut retdata_iterator = VecDeque::new();
        let mut retdata_construct = VecDeque::new();
        retdata_construct.push_back(12.into());
        retdata_iterator.push_back(retdata_construct);
        let mut handler = OsSyscallHandler {
            retdata_iterator,
            ..Default::default()
        };

        let vm = vm!();
        let ptr = Relocatable {
            segment_index: 0,
            offset: 0,
        };

        assert_matches!(
            handler._deploy(&vm, ptr),
            Err(SyscallHandlerError::UnexpectedConstructorRetdata)
        );
    }

    #[test]
    fn storage_deploy_err_retdata_iterator() {
        let mut handler = OsSyscallHandler::default();
        let vm = vm!();
        let ptr = Relocatable {
            segment_index: 0,
            offset: 0,
        };

        assert_matches!(
            handler._deploy(&vm, ptr),
            Err(SyscallHandlerError::IteratorEmpty)
        );
    }

    #[test]
    fn test_storage_read() {
        let mut execute_code_read_iterator = VecDeque::new();
        execute_code_read_iterator.push_back(12.into());
        execute_code_read_iterator.push_back(1444.into());
        let mut handler = OsSyscallHandler {
            execute_code_read_iterator,
            ..Default::default()
        };

        let addr = Address(0.into());
        assert_matches!(handler._storage_read(addr.clone()), Ok(value) if value == 12.into());
        assert_matches!(handler._storage_read(addr.clone()), Ok(value) if value == 1444.into());
        assert_matches!(
            handler._storage_read(addr),
            Err(SyscallHandlerError::IteratorEmpty)
        );
    }

    #[test]
    fn test_storage_write() {
        let mut execute_code_read_iterator = VecDeque::new();
        execute_code_read_iterator.push_back(12.into());
        let mut handler = OsSyscallHandler {
            execute_code_read_iterator,
            ..Default::default()
        };

        let addr = Address(0.into());
        let val: Felt252 = 0.into();

        handler._storage_write(addr.clone(), val.clone()).unwrap();
        handler._storage_write(addr, val).unwrap();
    }

    #[test]
    fn assert_iterators_exhausted_err_deployed() {
        let mut deployed_contracts_iterator = VecDeque::new();
        deployed_contracts_iterator.push_back(Address(12.into()));
        let handler = OsSyscallHandler {
            deployed_contracts_iterator,
            ..Default::default()
        };

        assert_matches!(
            handler.assert_iterators_exhausted(),
            Err(SyscallHandlerError::IteratorNotEmpty)
        )
    }

    #[test]
    fn assert_iterators_exhausted_err_retdata() {
        let mut retdata_iterator = VecDeque::new();
        retdata_iterator.push_back(VecDeque::new());
        let handler = OsSyscallHandler {
            retdata_iterator,
            ..Default::default()
        };

        assert_matches!(
            handler.assert_iterators_exhausted(),
            Err(SyscallHandlerError::IteratorNotEmpty)
        )
    }

    #[test]
    fn assert_iterators_exhausted_err_execute() {
        let mut execute_code_read_iterator = VecDeque::new();
        execute_code_read_iterator.push_back(12.into());
        let handler = OsSyscallHandler {
            execute_code_read_iterator,
            ..Default::default()
        };

        assert_matches!(
            handler.assert_iterators_exhausted(),
            Err(SyscallHandlerError::IteratorNotEmpty)
        )
    }

    #[test]
    fn assert_iterators_exhausted() {
        let handler = OsSyscallHandler::default();

        assert_matches!(handler.assert_iterators_exhausted(), Ok(()))
    }

    #[test]
    fn get_caller_address_err() {
        let mut handler = OsSyscallHandler::default();

        let vm = vm!();
        let ptr = Relocatable {
            segment_index: 0,
            offset: 0,
        };

        assert_matches!(
            handler._get_caller_address(&vm, ptr),
            Err(SyscallHandlerError::ListIsEmpty)
        )
    }

    #[test]
    fn get_caller_address() {
        let mut call_stack = VecDeque::new();
        call_stack.push_back(CallInfo::default());
        let mut handler = OsSyscallHandler {
            call_stack,
            ..Default::default()
        };
        let vm = vm!();
        let ptr = Relocatable {
            segment_index: 0,
            offset: 0,
        };
        assert_matches!(
            handler._get_caller_address(&vm, ptr),
            Ok(caller_address) if caller_address == CallInfo::default().caller_address
        )
    }

    #[test]
    fn exit_call() {
        let mut call_stack = VecDeque::new();
        call_stack.push_back(CallInfo::default());
        let mut handler = OsSyscallHandler {
            call_stack,
            ..Default::default()
        };

        assert_matches!(handler.exit_call(), Ok(Some(call_info)) if call_info == CallInfo::default())
    }

    #[test]
    fn enter_call_err() {
        let mut handler = OsSyscallHandler::default();

        assert_matches!(
            handler.enter_call(),
            Err(SyscallHandlerError::IteratorEmpty)
        )
    }

    #[test]
    fn enter_call() {
        let mut call_iterator = VecDeque::new();
        call_iterator.push_back(CallInfo::default());

        let mut handler = OsSyscallHandler {
            call_iterator,
            ..Default::default()
        };

        assert_matches!(handler.enter_call(), Ok(()))
    }

    #[test]
    fn allocate_segment() {
        let mut vm = vm!();
        let mut handler = OsSyscallHandler::default();
        let data = vec![
            MaybeRelocatable::from((0, 1)),
            MaybeRelocatable::from((0, 2)),
            MaybeRelocatable::from((0, 3)),
        ];

        assert_matches!(
            handler.allocate_segment(&mut vm, data),
            Ok(Relocatable {
                segment_index: -1,
                offset: 0
            })
        )
    }

    #[test]
    fn call_contract_and_write_response_err() {
        let retdata_iterator = vec![vec![12.into()].into(), vec![6543.into()].into()].into();
        let mut handler = OsSyscallHandler {
            retdata_iterator,
            ..Default::default()
        };

        let mut vm = vm!();
        let syscall_ptr = Relocatable {
            segment_index: 0,
            offset: 0,
        };
        assert_matches!(
            handler._call_contract_and_write_response("call_contract", &mut vm, syscall_ptr),
            Err(e) if e.to_string().contains(&MemoryError::UnallocatedSegment(0, 0).to_string())
        )
    }

    #[test]
    fn call_contract_and_write_response() {
        let retdata_iterator = vec![vec![12.into()].into(), vec![6543.into()].into()].into();
        let mut handler = OsSyscallHandler {
            retdata_iterator,
            ..Default::default()
        };

        let mut vm = vm!();
        let syscall_ptr = Relocatable {
            segment_index: 0,
            offset: 0,
        };

        vm.add_memory_segment();
        assert_matches!(
            handler._call_contract_and_write_response("call_contract", &mut vm, syscall_ptr),
            Ok(())
        );

        let addr_0 = (syscall_ptr + 5_i32).unwrap();
        assert_matches!(get_integer(&vm, addr_0), Ok(1));
        let addr_1 = (syscall_ptr + 6_i32).unwrap();
        assert_matches!(
            get_relocatable(&vm, addr_1),
            Ok(Relocatable {
                segment_index: -1,
                offset: 0
            })
        );
    }
}
