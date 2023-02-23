use super::state_objects::FeeInfo;
use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            execution_errors::ExecutionError,
            objects::{CallInfo, TransactionExecutionContext, TransactionExecutionInfo},
        },
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::{
            cached_state::CachedState,
            state_api::{State, StateReader},
        },
    },
    core::{
        contract_address::starknet_contract_address::compute_class_hash,
        errors::syscall_handler_errors::SyscallHandlerError,
        transaction_hash::starknet_transaction_hash::calculate_deploy_transaction_hash,
    },
    definitions::{general_config::StarknetGeneralConfig, transaction_type::TransactionType},
    hash_utils::calculate_contract_address,
    services::api::contract_class::{ContractClass, EntryPointType},
    starkware_utils::starkware_errors::StarkwareError,
    utils::{calculate_tx_resources, Address},
    utils_errors::UtilsError,
};
use felt::{felt_str, Felt};
use num_traits::Zero;
use std::collections::HashMap;

pub struct InternalDeploy {
    pub(crate) hash_value: Felt,
    pub(crate) version: u64,
    pub(crate) contract_address: Address,
    pub(crate) contract_address_salt: Address,
    pub(crate) contract_hash: [u8; 32],
    pub(crate) constructor_calldata: Vec<Felt>,
    pub(crate) tx_type: TransactionType,
}

impl InternalDeploy {
    pub fn new(
        contract_address_salt: Address,
        contract_class: ContractClass,
        constructor_calldata: Vec<Felt>,
        chain_id: Felt,
        version: u64,
    ) -> Result<Self, SyscallHandlerError> {
        let class_hash = compute_class_hash(&contract_class)
            .map_err(|_| SyscallHandlerError::ErrorComputingHash)?;
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

    pub fn class_hash(&self) -> [u8; 32] {
        self.contract_hash
    }

    pub fn _apply_specific_concurrent_changes<S: Default + State + StateReader + Clone>(
        &self,
        mut state: CachedState<S>,
        _general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, StarkwareError> {
        state.deploy_contract(self.contract_address.clone(), self.contract_hash)?;
        let class_hash: [u8; 32] = self.contract_hash[..]
            .try_into()
            .map_err(|_| StarkwareError::IncorrectClassHashSize)?;
        state.get_contract_class(&class_hash)?;

        self.handle_empty_constructor(&mut state)
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

    pub fn handle_empty_constructor<T: Default + State + StateReader + Clone>(
        &self,
        state: &mut T,
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

        let changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(call_info.clone())],
            self.tx_type.clone(),
            state,
            changes,
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

    pub fn invoke_constructor<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, ExecutionError> {
        let entry_point_selector = felt_str!(
            "1159040026212278395030414237414753050475174923702621880048416706425641521556"
        );
        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.constructor_calldata.clone(),
            entry_point_selector,
            Address(0.into()),
            EntryPointType::Constructor,
            None,
            None,
        );

        let tx_execution_context = TransactionExecutionContext::new(
            Address(Felt::zero()),
            self.hash_value.clone(),
            Vec::new(),
            0,
            Felt::zero(),
            general_config.invoke_tx_max_n_steps,
            self.version,
        );

        let mut resources_manager = ExecutionResourcesManager::default();
        let call_info = call.execute(
            state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
        )?;

        let changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(call_info.clone())],
            self.tx_type.clone(),
            state,
            changes,
            None,
        )?;

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                None,
                Some(call_info),
                actual_resources,
                Some(self.tx_type.clone()),
            ),
        )
    }
}
