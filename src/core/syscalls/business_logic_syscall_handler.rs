use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;
use num_traits::{One, Zero};

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
    services::api::{contract_class::EntryPointType, contract_class_errors::ContractClassError},
    utils::{felt_to_hash, get_felt_range, Address, ClassHash},
};

use super::{
    syscall_handler::SyscallHandler, syscall_info::get_syscall_size_from_name,
    syscall_request::SyscallRequest,
};

#[allow(unused)]
pub struct BusinessLogicSyscallHandler<'a, T: State + StateReader> {
    pub(crate) events: Vec<OrderedEvent>,
    pub(crate) expected_syscall_ptr: Relocatable,
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) tx_execution_context: TransactionExecutionContext,
    pub(crate) l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub(crate) internal_calls: Vec<CallInfo>,
    pub(crate) general_config: StarknetGeneralConfig,
    pub(crate) entry_point: ExecutionEntryPoint,
    pub(crate) starknet_storage_state: ContractStorageState<'a, T>,
}

impl<'a, T: Default + State + StateReader> BusinessLogicSyscallHandler<'a, T> {
    #[allow(unused)]
    /// Increments the syscall count for a given `syscall_name` by 1.
    fn increment_syscall_count(&mut self, syscall_name: &str) {
        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);
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

        // return a struct with other data
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

        let call_info = call
            .execute(
                self.starknet_storage_state.state,
                &self.general_config,
                &mut self.resources_manager,
                &self.tx_execution_context,
            )
            .map_err(|_| StateError::ExecutionEntryPoint())?;

        self.internal_calls.push(call_info.clone());

        Ok(call_info.result())
    }
}

impl<'a, T: Default + State + StateReader> SyscallHandler for BusinessLogicSyscallHandler<'a, T> {
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

    fn syscall_deploy(
        &mut self,
        vm: &VirtualMachine,
        syscall_request: SyscallRequest,
        remaining_gas: u64,
    ) -> Result<(Address, CallResult), SyscallHandlerError> {
        let SyscallRequest::Deploy(request) = syscall_request;

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
        _vm: &mut VirtualMachine,
        _data: Vec<cairo_rs::types::relocatable::MaybeRelocatable>,
    ) -> Result<Relocatable, SyscallHandlerError> {
        todo!()
    }
}
