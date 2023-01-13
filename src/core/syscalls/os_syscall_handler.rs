use super::syscall_handler::SyscallHandler;
use super::syscall_request::SyscallRequest;
use super::syscall_response::WriteSyscallResponse;
use crate::business_logic::state::state_api_objects::BlockInfo;
use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::services::api::contract_class::EntryPointType;
use crate::utils::Address;
use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::vm_core::VirtualMachine;
use cairo_rs::vm::vm_memory::memory_segments::MemorySegmentManager;
use std::any::Any;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CallInfo {
    caller_address: Address,
    contract_address: Address,
    internal_calls: Vec<CallInfo>,
    entry_point_type: Option<EntryPointType>,
    _storage_read_values: VecDeque<u64>, // u64
    retadata: VecDeque<u64>,
}

impl Default for CallInfo {
    fn default() -> Self {
        Self {
            caller_address: Address::new("0"),
            contract_address: Address::new("0"),
            internal_calls: Vec::new(),
            entry_point_type: Some(EntryPointType::Constructor),
            _storage_read_values: VecDeque::new(),
            retadata: VecDeque::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct OsSingleStarknetStorage;

#[derive(Debug, PartialEq)]
pub struct TransactionExecutionInfo;

impl OsSingleStarknetStorage {
    // Writes the given value in the given key in ongoing_storage_changes and returns the
    // previous value. This value is needed to create the DictAccess while executing the
    // corresponding storage_write system call.
    fn write(&self, _key: u64, _value: u64) -> u64 {
        // TO BE IMPLEMENTED
        todo!()
    }
}

#[derive(Debug, Default)]
pub(crate) struct OsSyscallHandler {
    tx_execution_info_iterator: VecDeque<TransactionExecutionInfo>,
    call_iterator: VecDeque<CallInfo>,

    //  A stack that keeps track of the state of the calls being executed now.
    // The last item is the state of the current call; the one before it, is the
    // state of the caller (the call the called the current call); and so on.
    call_stack: VecDeque<CallInfo>,
    // An iterator over contract addresses that were deployed during that call.
    deployed_contracts_iterator: VecDeque<Address>, // u64
    // An iterator to the retdata of its internal calls.
    retdata_iterator: VecDeque<VecDeque<u64>>, //VEC<u64>
    // An iterator to the read_values array which is consumed when the transaction
    // code is executed.
    execute_code_read_iterator: VecDeque<u64>, //u64
    // StarkNet storage members.
    starknet_storage_by_address: HashMap<u64, OsSingleStarknetStorage>,
    // A pointer to the Cairo TxInfo struct.
    // This pointer needs to match the TxInfo pointer that is going to be used during the system
    // call validation by the StarkNet OS.
    // Set during enter_tx.
    pub(crate) tx_info_ptr: Option<Relocatable>,
    // The TransactionExecutionInfo for the transaction currently being executed.
    tx_execution_info: Option<TransactionExecutionInfo>,
    block_info: BlockInfo,
}

impl SyscallHandler for OsSyscallHandler {
    fn emit_event(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        todo!()
    }

    fn library_call(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        todo!()
    }

    fn send_message_to_l1(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        Ok(())
    }

    fn _get_tx_info_ptr(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> Result<Relocatable, SyscallHandlerError> {
        Ok(*self
            .tx_info_ptr
            .as_ref()
            .ok_or(SyscallHandlerError::TxInfoPtrIsNone)?)
    }

    fn _deploy(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
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
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Vec<u64>, SyscallHandlerError> {
        Ok(self
            .retdata_iterator
            .pop_front()
            .ok_or(SyscallHandlerError::IteratorEmpty)?
            .into())
    }

    fn _get_caller_address(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        match self.call_stack.back() {
            None => Err(SyscallHandlerError::ListIsEmpty)?,
            Some(call_info) => Ok(call_info.caller_address.clone()),
        }
    }

    fn _get_contract_address(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Address, SyscallHandlerError> {
        match self.call_stack.front() {
            None => Err(SyscallHandlerError::ListIsEmpty)?,
            Some(call_info) => Ok(call_info.contract_address.clone()),
        }
    }

    fn _storage_read(&mut self, address: u64) -> Result<u64, SyscallHandlerError> {
        self.execute_code_read_iterator
            .pop_front()
            .ok_or(SyscallHandlerError::IteratorEmpty)
    }

    // Advance execute_code_read_iterators since the previous storage value is written
    // in each write operation. See BusinessLogicSysCallHandler._storage_write().
    fn _storage_write(&mut self, address: u64, value: u64) {
        self.execute_code_read_iterator.pop_front();
    }

    /// Allocates and returns a new temporary segment.
    fn allocate_segment(
        &mut self,
        vm: &mut VirtualMachine,
        data: Vec<MaybeRelocatable>,
    ) -> Result<Relocatable, SyscallHandlerError> {
        let segment_start = vm.add_temporary_segment();

        vm.write_arg(&segment_start, &data)
            .map_err(|_| SyscallHandlerError::WriteArg)?;
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
        retdata_iterator: VecDeque<VecDeque<u64>>,
        execute_code_read_iterator: VecDeque<u64>,
        starknet_storage_by_address: HashMap<u64, OsSingleStarknetStorage>,
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
    // Called when starting the execution of a transaction.
    // 'tx_info_ptr' is a pointer to the TxInfo struct corresponding to said transaction.
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

    fn exit_call(&mut self) -> Result<Option<CallInfo>, SyscallHandlerError> {
        self.assert_iterators_exhausted()?;
        Ok(self.call_stack.pop_front())
    }

    /// Called after the execution of the current transaction complete.
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
    fn execute_syscall_storage_write(
        &self,
        contract_address: &u64,
        key: u64,
        value: u64,
    ) -> Result<u64, SyscallHandlerError> {
        Ok(self
            .starknet_storage_by_address
            .get(contract_address)
            .ok_or(SyscallHandlerError::KeyNotFound)?
            .write(key, value))
    }

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
            .iter()
            .map(|call_info_internal| call_info_internal.retadata.clone())
            .collect::<VecDeque<VecDeque<u64>>>();

        self.execute_code_read_iterator = call_info._storage_read_values;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::business_logic::state::state_api_objects::BlockInfo;
    use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
    use crate::core::syscalls::syscall_handler::{SyscallHandler, SyscallHintProcessor};
    use crate::core::syscalls::syscall_request::CallContractRequest;
    use crate::utils::{get_integer, get_relocatable, test_utils::*, Address};
    use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
    use cairo_rs::vm::errors::memory_errors::MemoryError;
    use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
    use cairo_rs::vm::vm_core::VirtualMachine;
    use std::any::Any;
    use std::collections::{HashMap, VecDeque};

    use super::{CallInfo, OsSyscallHandler, TransactionExecutionInfo};
    use crate::core::syscalls::hint_code::GET_BLOCK_NUMBER;
    use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::HintProcessorData;
    use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;
    use cairo_rs::relocatable;
    use cairo_rs::types::exec_scope::ExecutionScopes;
    use std::borrow::Cow;

    #[test]
    fn get_contract_address() {
        let mut call_stack = VecDeque::new();
        let call_info = CallInfo {
            contract_address: Address::new("5"),
            caller_address: Address::new("1"),
            internal_calls: Vec::new(),
            entry_point_type: None,
            _storage_read_values: VecDeque::new(),
            retadata: VecDeque::new(),
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
        assert_eq!(get_contract_address, Ok(Address::new("5")))
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
        assert_eq!(get_contract_address, SyscallHandlerError::ListIsEmpty)
    }

    #[test]
    fn end_tx_err_execute_code_read_iterator() {
        let mut execute_code_read_iterator = VecDeque::new();
        execute_code_read_iterator.push_back(12);
        let mut handler = OsSyscallHandler {
            execute_code_read_iterator,
            ..Default::default()
        };

        assert_eq!(handler.end_tx(), Err(SyscallHandlerError::IteratorNotEmpty))
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

        assert_eq!(
            handler.end_tx(),
            Err(SyscallHandlerError::ShouldBeNone(String::from(
                "tx_info_ptr"
            )))
        )
    }

    #[test]
    fn end_tx_err_tx_execution_info() {
        let mut handler = OsSyscallHandler {
            tx_execution_info: Some(TransactionExecutionInfo),
            ..Default::default()
        };

        assert_eq!(
            handler.end_tx(),
            Err(SyscallHandlerError::ShouldBeNone(String::from(
                "tx_execution_info",
            )))
        )
    }

    #[test]
    fn end_tx() {
        let mut handler = OsSyscallHandler::default();

        assert_eq!(handler.end_tx(), Ok(()))
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

        assert_eq!(
            handler.start_tx(reloc),
            Err(SyscallHandlerError::ShouldBeNone(String::from(
                "tx_info_ptr"
            )))
        )
    }

    #[test]
    fn start_tx_err_tx_execution_info() {
        let tx_execution_info = Some(TransactionExecutionInfo);

        let mut handler = OsSyscallHandler {
            tx_execution_info,
            ..Default::default()
        };

        let reloc = Relocatable {
            segment_index: 1,
            offset: 1,
        };

        assert_eq!(
            handler.start_tx(reloc),
            Err(SyscallHandlerError::ShouldBeNone(String::from(
                "tx_execution_info",
            )))
        )
    }

    #[test]
    fn start_tx() {
        let mut handler = OsSyscallHandler::default();

        let reloc = Relocatable {
            segment_index: 0,
            offset: 0,
        };

        assert_eq!(handler.start_tx(reloc), Ok(()))
    }

    #[test]
    fn skip_tx() {
        let mut tx_execution_info_iterator = VecDeque::new();
        tx_execution_info_iterator.push_back(TransactionExecutionInfo);
        let mut handler = OsSyscallHandler {
            tx_execution_info_iterator,
            ..Default::default()
        };

        assert_eq!(handler.skip_tx(), Some(TransactionExecutionInfo));
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
        assert_eq!(
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

        assert_eq!(
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

        assert_eq!(handler._call_contract("", &vm, ptr), Ok(Vec::new()));
        assert_eq!(handler._call_contract("", &vm, ptr), Ok(Vec::new()));
        assert_eq!(
            handler._call_contract("", &vm, ptr),
            Err(SyscallHandlerError::IteratorEmpty)
        )
    }

    #[test]
    fn storage_deploy() {
        let mut retdata_iterator = VecDeque::new();
        retdata_iterator.push_back(VecDeque::new());
        let mut deployed_contracts_iterator = VecDeque::new();
        deployed_contracts_iterator.push_back(Address::new("12"));
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

        assert_eq!(handler._deploy(&vm, ptr), Ok(Address::new("12")));
    }

    #[test]
    fn storage_deploy_err_retdata_iterator_multiple() {
        let mut retdata_iterator = VecDeque::new();
        let mut retdata_construct = VecDeque::new();
        retdata_construct.push_back(12);
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

        assert_eq!(
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

        assert_eq!(
            handler._deploy(&vm, ptr),
            Err(SyscallHandlerError::IteratorEmpty)
        );
    }

    #[test]
    fn storage_read() {
        let mut execute_code_read_iterator = VecDeque::new();
        execute_code_read_iterator.push_back(12);
        execute_code_read_iterator.push_back(1444);
        let mut handler = OsSyscallHandler {
            execute_code_read_iterator,
            ..Default::default()
        };

        let addr = 0;
        assert_eq!(handler._storage_read(addr), Ok(12));
        assert_eq!(handler._storage_read(addr), Ok(1444));
        assert_eq!(
            handler._storage_read(addr),
            Err(SyscallHandlerError::IteratorEmpty)
        );
    }

    #[test]
    fn storage_write() {
        let mut execute_code_read_iterator = VecDeque::new();
        execute_code_read_iterator.push_back(12);
        let mut handler = OsSyscallHandler {
            execute_code_read_iterator,
            ..Default::default()
        };

        let addr = 0;
        let val = 0;

        handler._storage_write(addr, val);
        handler._storage_write(addr, val);
    }

    #[test]
    fn assert_iterators_exhausted_err_deployed() {
        let mut deployed_contracts_iterator = VecDeque::new();
        deployed_contracts_iterator.push_back(Address::new("12"));
        let handler = OsSyscallHandler {
            deployed_contracts_iterator,
            ..Default::default()
        };

        assert_eq!(
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

        assert_eq!(
            handler.assert_iterators_exhausted(),
            Err(SyscallHandlerError::IteratorNotEmpty)
        )
    }

    #[test]
    fn assert_iterators_exhausted_err_execute() {
        let mut execute_code_read_iterator = VecDeque::new();
        execute_code_read_iterator.push_back(12);
        let handler = OsSyscallHandler {
            execute_code_read_iterator,
            ..Default::default()
        };

        assert_eq!(
            handler.assert_iterators_exhausted(),
            Err(SyscallHandlerError::IteratorNotEmpty)
        )
    }

    #[test]
    fn assert_iterators_exhausted() {
        let handler = OsSyscallHandler::default();

        assert_eq!(handler.assert_iterators_exhausted(), Ok(()))
    }

    #[test]
    fn get_caller_address_err() {
        let mut handler = OsSyscallHandler::default();

        let vm = vm!();
        let ptr = Relocatable {
            segment_index: 0,
            offset: 0,
        };

        assert_eq!(
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
        assert_eq!(
            handler._get_caller_address(&vm, ptr),
            Ok(CallInfo::default().caller_address)
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

        assert_eq!(handler.exit_call(), Ok(Some(CallInfo::default())))
    }

    #[test]
    fn enter_call_err() {
        let mut handler = OsSyscallHandler::default();

        assert_eq!(
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

        assert_eq!(handler.enter_call(), Ok(()))
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

        assert_eq!(
            handler.allocate_segment(&mut vm, data),
            Ok(Relocatable {
                segment_index: -1,
                offset: 0
            })
        )
    }

    #[test]
    fn call_contract_and_write_response_err() {
        let retdata_iterator = vec![vec![12].into(), vec![6543].into()].into();
        let mut handler = OsSyscallHandler {
            retdata_iterator,
            ..Default::default()
        };

        let mut vm = vm!();
        let syscall_ptr = Relocatable {
            segment_index: 0,
            offset: 0,
        };
        assert_eq!(
            handler._call_contract_and_write_response("call_contract", &mut vm, syscall_ptr),
            Err(SyscallHandlerError::VirtualMachineError(
                VirtualMachineError::MemoryError(MemoryError::UnallocatedSegment(0, 0))
            ))
        )
    }
    #[test]
    fn call_contract_and_write_response() {
        let retdata_iterator = vec![vec![12].into(), vec![6543].into()].into();
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
        assert_eq!(
            handler._call_contract_and_write_response("call_contract", &mut vm, syscall_ptr),
            Ok(())
        );

        let addr_0 = Relocatable::from(&(syscall_ptr + 5));
        assert_eq!(get_integer(&vm, &addr_0), Ok(1));
        let addr_1 = Relocatable::from(&(syscall_ptr + 6));
        assert_eq!(
            get_relocatable(&vm, &addr_1),
            Ok(Relocatable {
                segment_index: -1,
                offset: 0
            })
        );
    }
}
