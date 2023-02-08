use std::collections::HashMap;

use crate::business_logic::execution::objects::{
    CallInfo, TransactionExecutionContext, TransactionExecutionInfo,
};
use crate::business_logic::fact_state::state::ExecutionResourcesManager;
use crate::business_logic::state::state_api::{State, StateReader};
use crate::business_logic::state::update_tracker_state::UpdatesTrackerState;
use crate::core::errors::state_errors::StateError;
use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::core::transaction_hash::starknet_transaction_hash::calculate_deploy_transaction_hash;
use crate::definitions::constants::TRANSACTION_VERSION;
use crate::definitions::general_config::{self, StarknetGeneralConfig};
use crate::definitions::transaction_type::TransactionType;
use crate::hash_utils::calculate_contract_address;
use crate::services::api::contract_class::{self, ContractClass};
use crate::starknet_storage::storage::{FactFetchingContext, Storage};
use crate::starkware_utils::starkware_errors::StarkwareError;
use crate::utils::{calculate_tx_resources, Address};
use crate::utils_errors::UtilsError;
use felt::Felt;
use num_traits::Zero;

use super::state_objects::FeeInfo;

pub struct InternalDeploy {
    hash_value: Felt,
    version: u64,
    contract_address: Address,
    contract_address_salt: Address,
    contract_hash: [u8; 32],
    constructor_calldata: Vec<Felt>,
    tx_type: TransactionType,
}

// TODO: this function is on another PR
fn compute_class_hash(contract_class: ContractClass) -> Felt {
    todo!()
}

impl InternalDeploy {
    pub fn new(
        contract_address_salt: Address,
        contract_class: ContractClass,
        constructor_calldata: Vec<Felt>,
        chain_id: u64,
        version: u64,
    ) -> Result<Self, SyscallHandlerError> {
        let class_hash = compute_class_hash(contract_class);
        let contract_hash: [u8; 32] = class_hash
            .to_string()
            .as_bytes()
            .try_into()
            .map_err(|_| UtilsError::FeltToFixBytesArrayFail(class_hash.clone()))?;
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
            contract_address_salt,
            contract_hash,
            constructor_calldata,
            tx_type: TransactionType::Deploy,
        })
    }

    pub fn create_for_testing<S: Storage>(
        ffc: FactFetchingContext<S>,
        contract_class: ContractClass,
        contract_address_salt: Address,
        constructor_calldata: Vec<Felt>,
        chain_id: Option<u64>,
    ) -> Result<Self, SyscallHandlerError> {
        InternalDeploy::new(
            contract_address_salt,
            contract_class,
            constructor_calldata,
            chain_id.unwrap_or(0),
            TRANSACTION_VERSION,
        )
    }

    pub fn class_hash(&self) -> [u8; 32] {
        self.contract_hash
    }

    pub fn get_state_selector() {
        todo!()
    }

    pub fn _apply_specific_concurrent_changes<S: State + StateReader>(
        &self,
        mut state: UpdatesTrackerState<S>,
        general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, StarkwareError> {
        state.deploy_contract(self.contract_address.clone(), self.contract_hash);
        let class_hash: [u8; 32] = self.contract_hash[..]
            .try_into()
            .map_err(|_| StarkwareError::IncorrectClassHashSize)?;
        let contract_class = state.get_contract_class(&class_hash);

        self.handle_empty_constructor(state)
    }

    pub fn _apply_specific_sequential_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, Felt>,
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

        let class_hash: [u8; 32] = self.contract_hash[..]
            .try_into()
            .map_err(|_| StarkwareError::IncorrectClassHashSize)?;
        let call_info = CallInfo::empty_constructor_call(
            self.contract_address.clone(),
            Address(0.into()),
            Some(class_hash),
        );

        let resources_manager = ExecutionResourcesManager {
            ..Default::default()
        };

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
        state: UpdatesTrackerState<S>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo {
        // TODO: uncomment once execute entry point has been implemented
        // let call = ExecuteEntryPoint.create()
        // let call_info = call.execute()
        // actual_resources = calculate_tx_resources()

        let tx_execution_context = TransactionExecutionContext::new(
            Address(Felt::zero()),
            self.hash_value.clone(),
            Vec::new(),
            0,
            Felt::zero(),
            general_config.invoke_tx_max_n_steps,
            self.version,
        );

        let resources_manager = ExecutionResourcesManager::default();
        todo!()
    }
}
