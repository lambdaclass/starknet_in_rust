use std::any::Any;
use std::collections::HashMap;

use super::syscall_request::*;
use super::syscall_response::{
    CallContractResponse, GetBlockTimestampResponse, GetCallerAddressResponse,
    GetSequencerAddressResponse, WriteSyscallResponse,
};
use crate::bigint;
use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::starknet_storage::errors::storage_errors::StorageError;
use crate::state::state_api_objects::BlockInfo;
use cairo_rs::any_box;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_rs::hint_processor::builtin_hint_processor::hint_utils::get_relocatable_from_var_name;
use cairo_rs::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_rs::serde::deserialize_program::ApTracking;
use cairo_rs::types::exec_scope::ExecutionScopes;
use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;

use super::business_logic_syscall_handler::BusinessLogicSyscallHandler;
use super::hint_code::*;

//* ---------------------
//* SyscallHandler Trait
//* ---------------------

pub(crate) trait SyscallHandler {
    fn emit_event(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;

    fn send_message_to_l1(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;

    fn get_tx_info(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;

    fn library_call(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;

    fn _get_tx_info_ptr(
        &mut self,
        vm: &mut VirtualMachine,
    ) -> Result<MaybeRelocatable, SyscallHandlerError>;

    fn _deploy(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<u32, SyscallHandlerError>;

    fn _read_and_validate_syscall_request(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;

    // Executes the contract call and fills the CallContractResponse struct.
    fn _call_contract_and_write_response(
        &mut self,
        syscall_name: &str,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let retdata = self._call_contract(syscall_name, vm, syscall_ptr).unwrap();

        let retdata_maybe_reloc = retdata
            .clone()
            .into_iter()
            .map(|item| MaybeRelocatable::from(bigint!(item)))
            .collect::<Vec<MaybeRelocatable>>();

        let response = CallContractResponse::new(
            retdata.len().try_into().unwrap(),
            self.allocate_segment(vm, retdata_maybe_reloc).unwrap(),
        );

        self._write_syscall_response(&response, vm, syscall_ptr)
    }

    fn _call_contract(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<Vec<u32>, SyscallHandlerError>;

    fn _get_caller_address(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<u64, SyscallHandlerError>;
    fn _get_contract_address(
        &self,
        vm: VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<u32, SyscallHandlerError>;
    fn _storage_read(&mut self, address: u32) -> Result<u32, SyscallHandlerError>;
    fn _storage_write(&mut self, address: u32, value: u32);
    fn allocate_segment(
        &mut self,
        vm: &mut VirtualMachine,
        data: Vec<MaybeRelocatable>,
    ) -> Result<Relocatable, SyscallHandlerError>;

    fn _write_syscall_response<T: WriteSyscallResponse>(
        &self,
        response: &T,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        response.write_syscall_response(vm, syscall_ptr)
    }

    fn get_sequencer_address(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let request = if let SyscallRequest::GetSequencerAddress(request) =
            self._read_and_validate_syscall_request("get_sequencer_address", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedGetSequencerAddressRequest);
        };

        let sequencer_address = self.get_block_info().sequencer_address;

        let response = GetSequencerAddressResponse::new(sequencer_address);

        response.write_syscall_response(vm, syscall_ptr)
    }

    fn read_syscall_request(
        &self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        match syscall_name {
            "emit_event" => EmitEventStruct::from_ptr(vm, syscall_ptr),
            "get_tx_info" => TxInfoStruct::from_ptr(vm, syscall_ptr),
            "deploy" => DeployRequestStruct::from_ptr(vm, syscall_ptr),
            "send_message_to_l1" => SendMessageToL1SysCall::from_ptr(vm, syscall_ptr),
            "library_call" => LibraryCallStruct::from_ptr(vm, syscall_ptr),
            "get_caller_address" => GetCallerAddressRequest::from_ptr(vm, syscall_ptr),
            "get_sequencer_address" => GetSequencerAddressRequest::from_ptr(vm, syscall_ptr),
            "get_block_timestamp" => GetBlockTimestampRequest::from_ptr(vm, syscall_ptr),
            _ => Err(SyscallHandlerError::UnknownSyscall),
        }
    }

    fn get_block_info(&self) -> &BlockInfo;

    fn get_block_timestamp(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let _request = if let SyscallRequest::GetBlockTimestamp(request) =
            self._read_and_validate_syscall_request("get_block_timestamp", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedGetBlockTimestampRequest);
        };

        let block_timestamp = self.get_block_info().block_timestamp;

        let response = GetBlockTimestampResponse::new(block_timestamp);

        response.write_syscall_response(vm, syscall_ptr)
    }

    fn get_caller_address(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let caller_address = self._get_caller_address(vm, syscall_ptr)?;
        let response = GetCallerAddressResponse::new(caller_address);
        response.write_syscall_response(vm, syscall_ptr)
    }
}

//* ------------------------
//* Structs implementations
//* ------------------------

pub(crate) struct SyscallHintProcessor<H: SyscallHandler> {
    pub(crate) builtin_hint_processor: BuiltinHintProcessor,
    #[allow(unused)] // TODO: remove after using.
    pub(crate) syscall_handler: H,
}

impl SyscallHintProcessor<BusinessLogicSyscallHandler> {
    #[allow(unused)] // TODO: Remove once used.
    pub fn new_empty(
    ) -> Result<SyscallHintProcessor<BusinessLogicSyscallHandler>, SyscallHandlerError> {
        Ok(SyscallHintProcessor {
            builtin_hint_processor: BuiltinHintProcessor::new_empty(),
            syscall_handler: BusinessLogicSyscallHandler::new(BlockInfo::default()),
        })
    }
}

impl<H: SyscallHandler> SyscallHintProcessor<H> {
    pub fn should_run_syscall_hint(
        &mut self,
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
        &mut self,
        vm: &mut VirtualMachine,
        _exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        _constants: &HashMap<String, BigInt>,
    ) -> Result<(), SyscallHandlerError> {
        let hint_data = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(SyscallHandlerError::WrongHintData)?;

        match &*hint_data.code {
            DEPLOY_SYSCALL_CODE => Err(SyscallHandlerError::NotImplemented),
            EMIT_EVENT_CODE => {
                let syscall_ptr = get_syscall_ptr(vm, &hint_data.ids_data, &hint_data.ap_tracking)?;
                self.syscall_handler.emit_event(vm, syscall_ptr)
            }
            GET_TX_INFO => {
                let syscall_ptr = get_syscall_ptr(vm, &hint_data.ids_data, &hint_data.ap_tracking)?;
                self.syscall_handler.get_tx_info(vm, syscall_ptr)
            }
            _ => Err(SyscallHandlerError::NotImplemented),
        }
    }
}

impl<H: SyscallHandler> HintProcessor for SyscallHintProcessor<H> {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, BigInt>,
    ) -> Result<(), VirtualMachineError> {
        if self.should_run_syscall_hint(vm, exec_scopes, hint_data, constants)? {
            self.execute_syscall_hint(vm, exec_scopes, hint_data, constants)
                .map_err(|e| VirtualMachineError::UnknownHint(e.to_string()))?;
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

fn get_syscall_ptr(
    vm: &VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<Relocatable, SyscallHandlerError> {
    let location = get_relocatable_from_var_name("syscall_ptr", vm, ids_data, ap_tracking)
        .map_err(|_| SyscallHandlerError::SegmentationFault)?;
    let syscall_ptr = vm
        .get_relocatable(&location)
        .map_err(|_| SyscallHandlerError::SegmentationFault)?;
    Ok(syscall_ptr)
}

#[cfg(test)]
mod tests {

    use crate::utils::get_integer;
    use crate::{add_segments, bigint, utils::test_utils::vm};
    use cairo_rs::relocatable;
    use num_bigint::{BigInt, Sign};

    use super::*;

    #[test]
    fn read_send_message_to_l1_request() {
        let syscall = BusinessLogicSyscallHandler::new(BlockInfo::default());
        let mut vm = vm!();
        add_segments!(vm, 3);

        vm.insert_value(&relocatable!(1, 0), bigint!(0)).unwrap();
        vm.insert_value(&relocatable!(1, 1), bigint!(1)).unwrap();
        vm.insert_value(&relocatable!(1, 2), bigint!(2)).unwrap();
        vm.insert_value(&relocatable!(1, 4), relocatable!(2, 0))
            .unwrap();

        assert_eq!(
            syscall.read_syscall_request("send_message_to_l1", &vm, relocatable!(1, 0)),
            Ok(SyscallRequest::SendMessageToL1(SendMessageToL1SysCall {
                _selector: bigint!(0),
                to_address: 1,
                payload_size: 2,
                payload_ptr: relocatable!(2, 0)
            }))
        )
    }

    #[test]
    fn read_deploy_syscall_request() {
        let syscall = BusinessLogicSyscallHandler::new(BlockInfo::default());
        let mut vm = vm!();
        add_segments!(vm, 2);

        vm.insert_value(&relocatable!(1, 0), bigint!(0)).unwrap();
        vm.insert_value(&relocatable!(1, 1), bigint!(1)).unwrap();
        vm.insert_value(&relocatable!(1, 2), bigint!(2)).unwrap();
        vm.insert_value(&relocatable!(1, 3), bigint!(3)).unwrap();
        vm.insert_value(&relocatable!(1, 4), relocatable!(1, 20))
            .unwrap();
        vm.insert_value(&relocatable!(1, 5), bigint!(4)).unwrap();

        assert_eq!(
            syscall.read_syscall_request("deploy", &vm, relocatable!(1, 0)),
            Ok(SyscallRequest::Deploy(DeployRequestStruct {
                _selector: bigint!(0),
                class_hash: bigint!(1),
                contract_address_salt: bigint!(2),
                constructor_calldata_size: bigint!(3),
                constructor_calldata: relocatable!(1, 20),
                deploy_from_zero: 4,
            }))
        )
    }

    #[test]
    fn get_block_timestamp_for_business_logic() {
        let mut syscall = BusinessLogicSyscallHandler::new(BlockInfo::default());
        let mut vm = vm!();
        add_segments!(vm, 2);

        vm.insert_value(&relocatable!(1, 0), bigint!(18)).unwrap();
        assert!(syscall
            .get_block_timestamp(&mut vm, relocatable!(1, 0))
            .is_ok());

        // Check that syscall.get_block_timestamp insert syscall.get_block_info().block_timestamp in the (1,1) position
        assert!(vm
            .insert_value(
                &relocatable!(1, 1),
                bigint!(syscall.get_block_info().block_timestamp + 10)
            )
            .is_err());
        assert!(vm
            .insert_value(
                &relocatable!(1, 1),
                bigint!(syscall.get_block_info().block_timestamp)
            )
            .is_ok())
    }

    #[test]
    fn get_sequencer_address_for_business_logic() {
        let mut syscall = BusinessLogicSyscallHandler::new(BlockInfo::default());
        let mut vm = vm!();
        add_segments!(vm, 2);

        vm.insert_value(&relocatable!(1, 0), bigint!(18)).unwrap();
        assert!(syscall
            .get_sequencer_address(&mut vm, relocatable!(1, 0))
            .is_ok());

        // Check that syscall.get_sequencer insert syscall.get_block_info().sequencer_address in the (1,1) position
        assert!(vm
            .insert_value(
                &relocatable!(1, 1),
                bigint!(syscall.get_block_info().sequencer_address + 10)
            )
            .is_err());
        assert!(vm
            .insert_value(
                &relocatable!(1, 1),
                bigint!(syscall.get_block_info().sequencer_address)
            )
            .is_ok())
    }

    #[test]
    fn get_caller_address_test() {
        let mut syscall = BusinessLogicSyscallHandler::new(BlockInfo::default());
        let mut vm = vm!();
        add_segments!(vm, 2);

        vm.insert_value(&relocatable!(1, 0), bigint!(18)).unwrap();
        // check that it wrote the response in the correct place
        assert!(syscall
            .get_caller_address(&mut vm, relocatable!(1, 0))
            .is_ok());
        assert_eq!(get_integer(&vm, &relocatable!(1, 1)).unwrap(), 0)
    }
}
