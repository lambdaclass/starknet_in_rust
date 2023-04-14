use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::vm_core::VirtualMachine,
};
use felt::Felt252;

use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, CallType, TransactionExecutionContext},
        },
        fact_state::state::ExecutionResourcesManager,
        state::{
            contract_storage_state::ContractStorageState,
            state_api::{State, StateReader},
        },
    },
    core::{
        errors::syscall_handler_errors::SyscallHandlerError,
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

pub struct BusinessLogicSyscallHandler<'a, T: Default + State + StateReader> {
    pub(crate) tx_execution_context: TransactionExecutionContext,
    /// A list of dynamically allocated segments that are expected to be read-only.
    pub(crate) read_only_segments: Vec<(Relocatable, MaybeRelocatable)>,
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) expected_syscall_ptr: Relocatable,
    pub(crate) caller_address: Address,
    pub(crate) general_config: StarknetGeneralConfig,
    pub(crate) starknet_storage_state: ContractStorageState<'a, T>,
    pub(crate) internal_calls: Vec<CallInfo>,
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
        let read_only_segments = vec![];
        let starknet_storage_state = ContractStorageState::new(state, contract_address);
        let internal_calls = vec![];
        Self {
            tx_execution_context,
            read_only_segments,
            resources_manager,
            expected_syscall_ptr,
            caller_address,
            general_config,
            starknet_storage_state,
            internal_calls,
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
}

impl<'a, T: Default + State + StateReader> SyscallHandler for BusinessLogicSyscallHandler<'a, T> {
    #[allow(irrefutable_let_patterns)]
    fn call_contract(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
        remaining_gas: u64,
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

        let result = call
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
