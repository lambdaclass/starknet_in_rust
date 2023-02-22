use super::{
    objects::internal_invoke_function::verify_no_calls_to_other_contracts, state_objects::FeeInfo,
};
use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            execution_errors::ExecutionError,
            objects::{CallInfo, TransactionExecutionContext, TransactionExecutionInfo},
        },
        fact_state::state::ExecutionResourcesManager,
        state::{
            state_api::{State, StateReader},
            update_tracker_state::UpdatesTrackerState,
        },
    },
    core::{
        contract_address::starknet_contract_address::compute_class_hash,
        errors::syscall_handler_errors::SyscallHandlerError,
        transaction_hash::starknet_transaction_hash::{
            calculate_deploy_account_transaction_hash, calculate_deploy_transaction_hash,
        },
    },
    definitions::{
        constants::{CONSTRUCTOR_ENTRY_POINT_SELECTOR, TRANSACTION_VERSION},
        general_config::{StarknetChainId, StarknetGeneralConfig},
        transaction_type::TransactionType,
    },
    hash_utils::calculate_contract_address,
    services::api::contract_class::{ContractClass, EntryPointType},
    starkware_utils::starkware_errors::StarkwareError,
    utils::{calculate_tx_resources, felt_to_hash, Address},
};
use felt::Felt;
use num_traits::Zero;
use std::collections::HashMap;

pub struct InternalDeploy {
    hash_value: Felt,
    version: u64,
    contract_address: Address,
    _contract_address_salt: Address,
    contract_hash: [u8; 32],
    constructor_calldata: Vec<Felt>,
    tx_type: TransactionType,
}

impl InternalDeploy {
    pub fn new(
        contract_address_salt: Address,
        contract_class: ContractClass,
        constructor_calldata: Vec<Felt>,
        chain_id: u64,
        version: u64,
    ) -> Result<Self, SyscallHandlerError> {
        let class_hash = compute_class_hash(&contract_class)
            .map_err(|_| SyscallHandlerError::ErrorComputingHash)?;
        let contract_hash: [u8; 32] = felt_to_hash(&class_hash);
        let contract_address = Address(calculate_contract_address(
            &contract_address_salt,
            &class_hash,
            &constructor_calldata[..],
            Address(0.into()),
        )?);

        let hash_value = calculate_deploy_transaction_hash(
            version,
            contract_address.clone(),
            &constructor_calldata,
            chain_id,
        )?;
        Ok(InternalDeploy {
            hash_value,
            version,
            contract_address,
            _contract_address_salt: contract_address_salt,
            contract_hash,
            constructor_calldata,
            tx_type: TransactionType::Deploy,
        })
    }

    pub fn class_hash(&self) -> [u8; 32] {
        self.contract_hash
    }

    pub fn _apply_specific_concurrent_changes<S: State + StateReader>(
        &self,
        mut state: UpdatesTrackerState<S>,
        _general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, StarkwareError> {
        state.deploy_contract(self.contract_address.clone(), self.contract_hash)?;
        let class_hash: [u8; 32] = self.contract_hash;
        state.get_contract_class(&class_hash)?;

        self.handle_empty_constructor(state)
    }

    pub fn _apply_specific_sequential_changes(
        &self,
        _state: impl State,
        _general_config: StarknetGeneralConfig,
        _actual_resources: HashMap<String, Felt>,
    ) -> FeeInfo {
        let fee_transfer_info = None;
        let actual_fee = 0;
        (fee_transfer_info, actual_fee)
    }

    pub fn handle_empty_constructor<S: State + StateReader>(
        &self,
        state: UpdatesTrackerState<S>,
    ) -> Result<TransactionExecutionInfo, StarkwareError> {
        if self.constructor_calldata.is_empty() {
            return Err(StarkwareError::TransactionFailed);
        }

        let class_hash: [u8; 32] = self.contract_hash;
        let call_info = CallInfo::empty_constructor_call(
            self.contract_address.clone(),
            Address(0.into()),
            Some(class_hash),
        );

        let resources_manager = ExecutionResourcesManager::default();

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(call_info.clone())],
            self.tx_type.clone(),
            state,
            None,
        )
        .map_err(|_| StarkwareError::UnexpectedHolesL2toL1Messages)?;

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                None,
                Some(call_info),
                actual_resources,
                Some(self.tx_type.clone()),
            ),
        )
    }

    pub fn invoke_constructor<S: State>(
        &self,
        _state: UpdatesTrackerState<S>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo {
        // TODO: uncomment once execute entry point has been implemented
        // let call = ExecuteEntryPoint.create()
        // let call_info = call.execute()
        // actual_resources = calculate_tx_resources()

        let _tx_execution_context = TransactionExecutionContext::new(
            Address(Felt::zero()),
            self.hash_value.clone(),
            Vec::new(),
            0,
            Felt::zero(),
            general_config.invoke_tx_max_n_steps,
            self.version,
        );

        let _resources_manager = ExecutionResourcesManager::default();
        todo!()
    }
}

#[derive(Clone, Debug, Default)]
pub struct InternalDeployAccount {
    contract_address: Address,
    _contract_address_salt: Address,
    class_hash: [u8; 32],
    constructor_calldata: Vec<Felt>,
    version: u64,
    nonce: u64,
}

impl InternalDeployAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_hash: [u8; 32],
        _max_fee: u64,
        version: u64,
        nonce: u64,
        constructor_calldata: Vec<Felt>,
        _signature: Vec<Felt>,
        contract_address_salt: Address,
        _chain_id: StarknetChainId,
    ) -> Result<Self, SyscallHandlerError> {
        let contract_address = calculate_contract_address(
            &contract_address_salt,
            &Felt::from_bytes_be(&class_hash),
            &constructor_calldata,
            Address(Felt::zero()),
        )?;

        // TODO: Remaining fields (from base class).
        Ok(Self {
            contract_address: Address(contract_address),
            _contract_address_salt: contract_address_salt,
            class_hash,
            constructor_calldata,
            version,
            nonce,
        })
    }

    pub fn new_for_testing(
        contract_class: &ContractClass,
        max_fee: u64,
        contract_address_salt: Address,
        constructor_calldata: Vec<Felt>,
        chain_id: StarknetChainId,
        signature: Vec<Felt>,
    ) -> Result<Self, SyscallHandlerError> {
        Self::new(
            felt_to_hash(&compute_class_hash(contract_class).unwrap()),
            max_fee,
            TRANSACTION_VERSION,
            0,
            constructor_calldata,
            signature,
            contract_address_salt,
            chain_id,
        )
    }

    pub fn get_state_selector(&self, _general_config: StarknetGeneralConfig) -> ! {
        todo!()
    }

    fn _apply_specific_concurrent_changes<S>(
        &self,
        _status: UpdatesTrackerState<S>,
        _general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo
    where
        S: State,
    {
        todo!()
    }

    pub fn handle_constructor<S>(
        &self,
        contract_class: ContractClass,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
        resources_manager: &mut ExecutionResourcesManager,
    ) -> Result<CallInfo, ExecutionError>
    where
        S: Clone + Default + State + StateReader,
    {
        let num_constructors = contract_class
            .entry_points_by_type
            .get(&EntryPointType::Constructor)
            .map(Vec::len)
            .unwrap_or(0);

        match num_constructors {
            0 => {
                if !self.constructor_calldata.is_empty() {
                    todo!()
                }

                Ok(CallInfo::empty_constructor_call(
                    self.contract_address.clone(),
                    Address(Felt::zero()),
                    Some(self.class_hash),
                ))
            }
            _ => self.run_constructor_entrypoint(state, general_config, resources_manager),
        }
    }

    pub fn run_constructor_entrypoint<S>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
        resources_manager: &mut ExecutionResourcesManager,
    ) -> Result<CallInfo, ExecutionError>
    where
        S: Clone + Default + State + StateReader,
    {
        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.constructor_calldata.clone(),
            CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone(),
            Address(Felt::zero()),
            EntryPointType::Constructor,
            None,
            None,
        );

        let call_info = call.execute(
            state,
            general_config,
            resources_manager,
            &self.get_execution_context(general_config.validate_max_n_steps),
        )?;

        verify_no_calls_to_other_contracts(&call_info)?;
        Ok(call_info)
    }

    pub fn get_execution_context(&self, n_steps: u64) -> TransactionExecutionContext {
        TransactionExecutionContext::new(
            self.contract_address.clone(),
            calculate_deploy_account_transaction_hash(
                self.version,
                &self.contract_address,
                self.class_hash,
                &self.constructor_calldata,
                todo!("max_fee"),
                self.nonce,
                self._contract_address_salt,
                todo!("chain_id"),
            ),
            todo!("signature"),
            todo!("self.max_fee"),
            self.nonce.into(),
            n_steps,
            self.version,
        )
    }
}
