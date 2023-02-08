use std::collections::HashMap;

use crate::business_logic::execution::execution_entry_point::ExecutionEntryPoint;
use crate::business_logic::execution::objects::{
    CallInfo, TransactionExecutionContext, TransactionExecutionInfo,
};
use crate::business_logic::fact_state::in_memory_state_reader::InMemoryStateReader;
use crate::business_logic::fact_state::state::ExecutionResourcesManager;
use crate::business_logic::state::cached_state::CachedState;
use crate::business_logic::state::state_api::{State, StateReader};
use crate::business_logic::state::update_tracker_state::UpdatesTrackerState;
use crate::core::contract_address::starknet_contract_address::compute_class_hash;
use crate::core::errors::state_errors::StateError;
use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::core::transaction_hash::starknet_transaction_hash::{
    calculate_deploy_transaction_hash, calculate_transaction_hash_common, TransactionHashPrefix,
};
use crate::definitions::constants::TRANSACTION_VERSION;
use crate::definitions::general_config::{self, StarknetGeneralConfig};
use crate::definitions::transaction_type::TransactionType;
use crate::hash_utils::calculate_contract_address_from_hash;
use crate::services::api::contract_class::{self, ContractClass, EntryPointType};
use crate::starknet_storage::storage::{FactFetchingContext, Storage};
use crate::starkware_utils::starkware_errors::StarkwareError;
use crate::utils::{calculate_tx_resources, preprocess_invoke_function_fields, Address};
use crate::utils_errors::UtilsError;
use felt::Felt;
use num_traits::Zero;

use super::error::TransactionError;
use super::state_objects::{FeeInfo, InternalStateTransaction};

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/// Represents an internal transaction in the StarkNet network that is a deployment of a Cairo
/// contract.
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
pub struct InternalDeploy {
    hash_value: Felt,
    version: u64,
    pub(crate) contract_address: Address,
    contract_address_salt: Address,
    pub(crate) contract_hash: [u8; 32],
    constructor_calldata: Vec<Felt>,
    tx_type: TransactionType,
}
// ------------------------------------------------------------
//                      Functions
// ------------------------------------------------------------
impl InternalDeploy {
    pub fn new(
        contract_address_salt: Address,
        contract_class: ContractClass,
        constructor_calldata: Vec<Felt>,
        chain_id: u64,
        version: u64,
    ) -> Result<Self, SyscallHandlerError> {
        let class_hash = compute_class_hash(&contract_class)
            .map_err(|_| SyscallHandlerError::FailToComputeHash)?;
        let contract_hash: [u8; 32] = class_hash
            .to_string()
            .as_bytes()
            .try_into()
            .map_err(|_| UtilsError::FeltToFixBytesArrayFail(class_hash.clone()))?;
        let contract_address = Address(calculate_contract_address_from_hash(
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

    pub(crate) fn invoke_constructor<S: State + StateReader>(
        &self,
        state: UpdatesTrackerState<S>,
        general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let entry_point_selector = Felt::from_bytes_be("constructor".as_bytes());
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

        // TODO: fix the issue with update tracker state and delete the default

        let call_info = CallInfo::default();
        // let call_info = call.execute(
        //     state,
        //     general_config,
        //     &mut resources_manager,
        //     tx_execution_context,
        // )?;

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(call_info.clone())],
            self.tx_type.clone(),
            state,
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

// ------------------------------------------------------------
//                   Trait implementation
// ------------------------------------------------------------

impl InternalStateTransaction for InternalDeploy {
    fn apply_specific_concurrent_changes<S: State + StateReader>(
        &self,
        state: UpdatesTrackerState<S>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo {
        todo!()
    }

    fn apply_specific_sequential_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, usize>,
    ) -> FeeInfo {
        todo!()
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
///  Represents an internal transaction in the StarkNet network that is a declaration of a Cairo
///  contract class.
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
pub(crate) struct InternalDeclare {
    pub(crate) class_hash: [u8; 32],
    pub(crate) sender_address: Address,
    pub(crate) tx_type: TransactionType,
    pub(crate) validate_entry_point_selector: Felt,
    pub(crate) version: usize,
    pub(crate) max_fee: u64,
    pub(crate) signature: Vec<Felt>,
    pub(crate) nonce: Felt,
}

// ------------------------------------------------------------
//                        Functions
// ------------------------------------------------------------
impl InternalDeclare {
    pub fn new(
        contract_class: ContractClass,
        chain_id: u64,
        sender_address: Address,
        max_fee: u64,
        version: usize,
        signature: Vec<Felt>,
        nonce: Felt,
    ) -> Result<Self, TransactionError> {
        let hash = compute_class_hash(&contract_class)?;
        let class_hash = hash
            .to_string()
            .as_bytes()
            .try_into()
            .map_err(|_| UtilsError::FeltToFixBytesArrayFail(hash.clone()))?;

        let validate_entry_point_selector = Felt::from_bytes_be("__validate_declare__".as_bytes());

        Ok(InternalDeclare {
            class_hash,
            sender_address,
            tx_type: TransactionType::Declare,
            validate_entry_point_selector,
            version,
            max_fee,
            signature,
            nonce,
        })
    }
}

// ------------------------------------------------------------
//                   Trait implementation
// ------------------------------------------------------------
impl InternalStateTransaction for InternalDeclare {
    fn apply_specific_concurrent_changes<S: State + StateReader>(
        &self,
        state: UpdatesTrackerState<S>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo {
        todo!()
    }

    fn apply_specific_sequential_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, usize>,
    ) -> FeeInfo {
        todo!()
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
///   Represents an internal transaction in the StarkNet network that is an invocation of a Cairo
///   contract function.
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
pub(crate) struct InternalInvokeFunction {
    contract_address: Address,
    entry_point_selector: Felt,
    entry_point_type: EntryPointType,
    calldata: Vec<Felt>,
    tx_type: TransactionType,
    version: u64,
    max_fee: u64,
    singature: Vec<Felt>,
    nonce: Option<Felt>,
    hash_value: Felt,
}

// ------------------------------------------------------------
//                        Functions
// ------------------------------------------------------------

impl InternalInvokeFunction {
    pub fn new(
        contract_address: Address,
        entry_point_selector: Felt,
        max_fee: u64,
        calldata: Vec<Felt>,
        singature: Vec<Felt>,
        chain_id: u64,
        nonce: Option<Felt>,
    ) -> Result<Self, TransactionError> {
        let version = TRANSACTION_VERSION;
        let (entry_point_selector_field, additional_data) = preprocess_invoke_function_fields(
            entry_point_selector.clone(),
            nonce.clone(),
            max_fee,
            version,
        )?;

        let hash_value = calculate_transaction_hash_common(
            TransactionHashPrefix::Invoke,
            version,
            contract_address.clone(),
            entry_point_selector_field,
            &calldata,
            max_fee,
            chain_id,
            &additional_data,
        )?;

        Ok(InternalInvokeFunction {
            contract_address,
            entry_point_selector,
            entry_point_type: EntryPointType::External,
            calldata,
            tx_type: TransactionType::InvokeFunction,
            version,
            max_fee,
            singature,
            nonce,
            hash_value,
        })
    }
}

impl InternalStateTransaction for InternalInvokeFunction {
    fn apply_specific_concurrent_changes<S: State + StateReader>(
        &self,
        state: UpdatesTrackerState<S>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo {
        todo!()
    }

    fn apply_specific_sequential_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, usize>,
    ) -> FeeInfo {
        todo!()
    }
}
