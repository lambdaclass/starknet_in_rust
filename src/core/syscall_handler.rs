use std::any::Any;
use std::collections::{HashMap, VecDeque};

use cairo_rs::any_box;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_rs::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_rs::types::exec_scope::ExecutionScopes;
use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use cairo_rs::vm::vm_memory::memory_segments::MemorySegmentManager;
use num_bigint::BigInt;

use crate::errors::StarknetError;

const DEPLOY_SYSCALL_CODE: &str =
    "syscall_handler.deploy(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub struct SyscallHintProcessor<H: SyscallHandler> {
    builtin_hint_processor: BuiltinHintProcessor,
    _syscall_handler: H,
}

impl SyscallHintProcessor<BusinessLogicSyscallHandler> {
    pub fn new_empty() -> SyscallHintProcessor<BusinessLogicSyscallHandler> {
        SyscallHintProcessor {
            builtin_hint_processor: BuiltinHintProcessor::new_empty(),
            _syscall_handler: BusinessLogicSyscallHandler,
        }
    }
}
impl<H: SyscallHandler> SyscallHintProcessor<H> {
    pub fn should_run_syscall_hint(
        &self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, BigInt>,
    ) -> Result<bool, VirtualMachineError> {
        match self
            .builtin_hint_processor
            .execute_hint(vm, exec_scopes, hint_data, constants)
        {
            Ok(()) => Ok(false),
            Err(VirtualMachineError::UnknownHint(_)) => Ok(true),
            Err(e) => Err(e),
        }
    }

    fn execute_syscall_hint(
        &self,
        _vm: &mut VirtualMachine,
        _exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        _constants: &HashMap<String, BigInt>,
    ) -> Result<(), VirtualMachineError> {
        println!("Hello from SyscallHintProcessor");

        let hint_data = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(VirtualMachineError::WrongHintData)?;

        match &*hint_data.code {
            DEPLOY_SYSCALL_CODE => {
                println!("Running deploy syscall.");
                Err(VirtualMachineError::NotImplemented)
            }
            _ => Err(VirtualMachineError::NotImplemented),
        }
    }
}

impl<H: SyscallHandler> HintProcessor for SyscallHintProcessor<H> {
    fn execute_hint(
        &self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, BigInt>,
    ) -> Result<(), VirtualMachineError> {
        if self.should_run_syscall_hint(vm, exec_scopes, hint_data, constants)? {
            self.execute_syscall_hint(vm, exec_scopes, hint_data, constants)?
        }

        Ok(())
    }

    fn compile_hint(
        &self,
        hint_code: &str,
        ap_tracking_data: &cairo_rs::serde::deserialize_program::ApTracking,
        reference_ids: &std::collections::HashMap<String, usize>,
        references: &std::collections::HashMap<
            usize,
            cairo_rs::hint_processor::hint_processor_definition::HintReference,
        >,
    ) -> Result<Box<dyn Any>, VirtualMachineError> {
        Ok(any_box!(HintProcessorData {
            code: hint_code.to_string(),
            ap_tracking: ap_tracking_data.clone(),
            ids_data: get_ids_data(reference_ids, references)?,
        }))
    }
}

fn get_ids_data(
    reference_ids: &HashMap<String, usize>,
    references: &HashMap<usize, HintReference>,
) -> Result<HashMap<String, HintReference>, VirtualMachineError> {
    let mut ids_data = HashMap::<String, HintReference>::new();
    for (path, ref_id) in reference_ids {
        let name = path
            .rsplit('.')
            .next()
            .ok_or(VirtualMachineError::FailedToGetIds)?;
        ids_data.insert(
            name.to_string(),
            references
                .get(ref_id)
                .ok_or(VirtualMachineError::FailedToGetIds)?
                .clone(),
        );
    }
    Ok(ids_data)
}

pub trait SyscallHandler {}

#[derive(Clone)]
struct CallInfo {
    _caller_address: u32,
    contract_address: u32,
    internal_calls: Vec<CallInfo>,
    entry_point_type: Option<EntryPointType>,
    _storage_read_values: VecDeque<u32>, // U32
    retadata: VecDeque<u32>,
}

#[derive(PartialEq, Clone)]
enum EntryPointType {
    External,
    L1Handler,
    Constructor,
}

struct OsSingleStarknetStorage;

pub struct BusinessLogicSyscallHandler;

pub struct TransactionExecutionInfo;

impl SyscallHandler for BusinessLogicSyscallHandler {}

impl OsSingleStarknetStorage {
    // Writes the given value in the given key in ongoing_storage_changes and returns the
    // previous value. This value is needed to create the DictAccess while executing the
    // corresponding storage_write system call.
    fn write(&self, _key: u32, _value: u32) -> u32 {
        // TO BE IMPLEMENTED
        0
    }
}

struct OsSyscallHandler {
    tx_execution_info_iterator: VecDeque<TransactionExecutionInfo>, //TRANSACTION EXECUTION INFO
    call_iterator: VecDeque<CallInfo>,                              // CALLINFO

    //  A stack that keeps track of the state of the calls being executed now.
    // The last item is the state of the current call; the one before it, is the
    // state of the caller (the call the called the current call); and so on.
    call_stack: VecDeque<CallInfo>,
    // An iterator over contract addresses that were deployed during that call.
    deployed_contracts_iterator: VecDeque<u32>, // U32
    // An iterator to the retdata of its internal calls.
    retdata_iterator: VecDeque<VecDeque<u32>>, //VEC<U32>
    // An iterator to the read_values array which is consumed when the transaction
    // code is executed.
    execute_code_read_iterator: VecDeque<u32>, //u32
    // StarkNet storage members.
    starknet_storage_by_address: HashMap<u32, OsSingleStarknetStorage>,
    // A pointer to the Cairo TxInfo struct.
    // This pointer needs to match the TxInfo pointer that is going to be used during the system
    // call validation by the StarkNet OS.
    // Set during enter_tx.
    tx_info_ptr: Option<Relocatable>,
    // The TransactionExecutionInfo for the transaction currently being executed.
    tx_execution_info: Option<TransactionExecutionInfo>,
}

impl OsSyscallHandler {
    // Called when starting the execution of a transaction.
    // 'tx_info_ptr' is a pointer to the TxInfo struct corresponding to said transaction.
    fn start_tx(&mut self, tx_info_ptr: Relocatable) -> Result<(), StarknetError> {
        match self.tx_info_ptr {
            None => (),
            Some(_) => Err(StarknetError::ShouldBeNone(String::from("tx_info_ptr")))?,
        }

        self.tx_info_ptr = Some(tx_info_ptr);

        match self.tx_execution_info {
            None => (),
            Some(_) => Err(StarknetError::ShouldBeNone(String::from(
                "tx_execution_info",
            )))?,
        }

        self.tx_execution_info = self.tx_execution_info_iterator.pop_front();
        // TO BE IMPLEMENTED
        // self.call_iterator = self.tx_execution_info.gen_call_iterator(); TO BE IMPLEMENTED
        Ok(())
    }

    fn skip_tx(&mut self) -> Option<TransactionExecutionInfo> {
        self.tx_execution_info_iterator.pop_front()
    }

    fn _storage_read(&mut self) -> Option<u32> {
        self.execute_code_read_iterator.pop_front()
    }

    fn _get_tx_info_ptr(self) -> Option<Relocatable> {
        self.tx_info_ptr
    }

    fn _call_contract(&mut self) -> Option<VecDeque<u32>> {
        self.retdata_iterator.pop_front()
    }

    fn _deploy(&mut self) -> Result<Option<u32>, StarknetError> {
        let constructor_retdata = self.retdata_iterator.pop_front().unwrap();
        match constructor_retdata.len() {
            0 => (),
            _ => Err(StarknetError::UnexpectedConstructorRetdata)?,
        }
        Ok(self.deployed_contracts_iterator.pop_front())
    }

    // Advance execute_code_read_iterators since the previous storage value is written
    // in each write operation. See BusinessLogicSysCallHandler._storage_write().
    fn _storage_write(&mut self) -> Option<u32> {
        self.execute_code_read_iterator.pop_front()
    }

    fn assert_iterators_exhausted(&self) -> Result<(), StarknetError> {
        match self.deployed_contracts_iterator.front() {
            None => (),
            Some(_) => Err(StarknetError::IteratorNotEmpty)?,
        };
        match self.retdata_iterator.front() {
            None => (),
            Some(_) => Err(StarknetError::IteratorNotEmpty)?,
        };
        match self.execute_code_read_iterator.front() {
            None => (),
            Some(_) => Err(StarknetError::IteratorNotEmpty)?,
        };
        Ok(())
    }

    fn exit_call(&mut self) -> Result<Option<CallInfo>, StarknetError> {
        self.assert_iterators_exhausted()?;
        Ok(self.call_stack.pop_front())
    }

    fn _get_caller_address(self) -> Result<u32, StarknetError> {
        match self.call_stack.front() {
            None => Err(StarknetError::ListIsEmpty)?,
            Some(call_info) => Ok(call_info._caller_address),
        }
    }

    fn _get_contract_address(self) -> Result<u32, StarknetError> {
        match self.call_stack.front() {
            None => Err(StarknetError::ListIsEmpty)?,
            Some(call_info) => Ok(call_info.contract_address),
        }
    }

    /// Called after the execution of the current transaction complete.
    fn end_tx(&mut self) -> Result<(), StarknetError> {
        match self.execute_code_read_iterator.front() {
            None => (),
            Some(_) => Err(StarknetError::IteratorNotEmpty)?,
        };
        match self.tx_info_ptr {
            None => (),
            Some(_) => Err(StarknetError::ShouldBeNone(String::from("tx_info_ptr")))?,
        }
        self.tx_info_ptr = None;

        match self.tx_execution_info {
            None => (),
            Some(_) => Err(StarknetError::ShouldBeNone(String::from(
                "tx_execution_info",
            )))?,
        }
        self.tx_execution_info = None;
        Ok(())
    }

    /// Allocates and returns a new temporary segment.
    fn _allocate_segment(
        self,
        mut vm: VirtualMachine,
        data: &dyn Any,
    ) -> Result<Relocatable, StarknetError> {
        let segment_start = vm.add_temporary_segment();
        vm.write_arg(&segment_start, data)
            .map_err(|_| StarknetError::WriteArg)?;
        Ok(segment_start)
    }

    /// Updates the cached storage and returns the storage value before
    /// the write operation.
    fn execute_syscall_storage_write(
        self,
        contract_address: &u32,
        key: u32,
        value: u32,
    ) -> Result<u32, StarknetError> {
        Ok(self
            .starknet_storage_by_address
            .get(contract_address)
            .ok_or(StarknetError::KeyNotFound)?
            .write(key, value))
    }

    fn enter_call(&mut self) -> Result<(), StarknetError> {
        self.assert_iterators_exhausted()?;

        let call_info = self
            .call_iterator
            .pop_front()
            .ok_or(StarknetError::IteratorEmpty)?;
        self.call_stack.push_back(call_info.clone());

        self.deployed_contracts_iterator = call_info
            .internal_calls
            .iter()
            .filter(|call_info_internal| {
                call_info_internal.entry_point_type == Some(EntryPointType::Constructor)
            })
            .map(|call_info_internal| call_info_internal.contract_address)
            .collect::<VecDeque<u32>>();

        self.retdata_iterator = call_info
            .internal_calls
            .iter()
            .map(|call_info_internal| call_info_internal.retadata.clone())
            .collect::<VecDeque<VecDeque<u32>>>();

        self.execute_code_read_iterator = call_info._storage_read_values;

        Ok(())
    }

    /// Returns the system call request written in the syscall segment, starting at syscall_ptr.
    /// Does not perform validations on the request, since it was validated in the BL.
    fn _read_and_validate_syscall_request(
        &self,
        _syscall_name: String,
        _segments: MemorySegmentManager,
        _syscall_ptr: Relocatable,
    ) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::core::syscall_handler::{SyscallHintProcessor, DEPLOY_SYSCALL_CODE};
    use crate::utils::test_utils::*;
    use cairo_rs::any_box;
    use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
        BuiltinHintProcessor, HintProcessorData,
    };
    use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;
    use cairo_rs::types::exec_scope::ExecutionScopes;
    use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
    use cairo_rs::vm::errors::memory_errors::MemoryError;
    use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
    use cairo_rs::vm::vm_core::VirtualMachine;
    use num_bigint::{BigInt, Sign};
    use std::any::Any;
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
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 6)),
                    MaybeRelocatable::from((1, 6)),
                    MaybeRelocatable::from((3, 0))
                )
            ))
        );
    }

    // tests that we are executing correctly our syscall hint processor.
    #[test]
    fn cannot_run_syscall_hints() {
        let hint_code = DEPLOY_SYSCALL_CODE;
        let mut vm = vm!();
        assert_eq!(
            run_syscall_hint!(vm, HashMap::new(), hint_code),
            Err(VirtualMachineError::NotImplemented)
        );
    }
}
