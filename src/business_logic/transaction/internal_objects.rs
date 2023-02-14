use std::collections::HashMap;

use crate::business_logic::execution::execution_entry_point::ExecutionEntryPoint;
use crate::business_logic::execution::execution_errors::ExecutionError;
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
    calculate_declare_transaction_hash, calculate_deploy_transaction_hash,
};
use crate::definitions::constants::TRANSACTION_VERSION;
use crate::definitions::general_config::{self, StarknetGeneralConfig};
use crate::definitions::transaction_type::TransactionType;
use crate::hash_utils::calculate_contract_address;
use crate::services::api::contract_class::{self, ContractClass, EntryPointType};
use crate::starknet_storage::storage::{FactFetchingContext, Storage};
use crate::starkware_utils::starkware_errors::StarkwareError;
use crate::utils::{calculate_tx_resources, verify_no_calls_to_other_contracts, Address};
use crate::utils_errors::UtilsError;
use cairo_rs::types::instruction::Res;
use felt::Felt;
use num_traits::{Num, Zero};

use super::error::TransactionError;
use super::state_objects::{FeeInfo, InternalStateTransaction};

pub struct InternalDeploy {
    hash_value: Felt,
    version: u64,
    contract_address: Address,
    contract_address_salt: Address,
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

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
///  Represents an internal transaction in the StarkNet network that is a declaration of a Cairo
///  contract class.
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
pub(crate) struct InternalDeclare {
    pub(crate) class_hash: [u8; 32],
    pub(crate) sender_address: Address,
    pub(crate) tx_type: TransactionType,
    pub(crate) validate_entry_point_selector: Felt,
    pub(crate) version: u64,
    pub(crate) max_fee: u64,
    pub(crate) signature: Vec<Felt>,
    pub(crate) nonce: Felt,
    pub(crate) hash_value: Felt,
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
        version: u64,
        signature: Vec<Felt>,
        nonce: Felt,
    ) -> Result<Self, TransactionError> {
        let hash = compute_class_hash(&contract_class.clone())?;
        let class_hash = hash
            .to_string()
            .as_bytes()
            .try_into()
            .map_err(|_| UtilsError::FeltToFixBytesArrayFail(hash.clone()))?;

        let hash_value = calculate_declare_transaction_hash(
            contract_class,
            chain_id,
            sender_address.clone(),
            max_fee,
            version,
            nonce.clone(),
        )?;

        let validate_entry_point_selector = Felt::from_str_radix(
            "626969833899987279399947180575486623810258720106406659648356883742278317941",
            10,
        )
        .unwrap();

        let internal_declare = InternalDeclare {
            class_hash,
            sender_address,
            tx_type: TransactionType::Declare,
            validate_entry_point_selector,
            version,
            max_fee,
            signature,
            nonce,
            hash_value,
        };

        internal_declare.verify_version();
        Ok(internal_declare)
    }

    pub fn account_contract_address(&self) -> Address {
        self.sender_address.clone()
    }

    pub fn validate_entrypoint_calldata(&self) -> [u8; 32] {
        self.class_hash
    }

    pub fn verify_version(&self) -> Result<(), TransactionError> {
        // no need to check if its lesser than 0 because it is an usize
        if self.version > u64::pow(2, 128) {
            return Err(TransactionError::StarknetError(
                "The sender_address field in Declare transactions of version 0, sender should be 1"
                    .to_string(),
            ));
        }

        if !self.max_fee.is_zero() {
            return Err(TransactionError::StarknetError(
                "The max_fee field in Declare transactions of version 0 must be 0.".to_string(),
            ));
        }

        if !self.nonce.is_zero() {
            return Err(TransactionError::StarknetError(
                "The nonce field in Declare transactions of version 0 must be 0.".to_string(),
            ));
        }

        if !self.signature.len().is_zero() {
            return Err(TransactionError::StarknetError(
                "The signature field in Declare transactions must be an empty list.".to_string(),
            ));
        }
        Ok(())
    }

    pub fn _apply_specific_concurrent_changes<T: State + StateReader>(
        &self,
        state: CachedState<InMemoryStateReader>,
        validate_info: Option<CallInfo>,
        general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        self.verify_version()?;
        // validate transaction
        let resources_manager = ExecutionResourcesManager::default();
        let updates_tracker_state = UpdatesTrackerState::new(state.clone());
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &vec![validate_info.clone()],
            TransactionType::Declare,
            updates_tracker_state,
            None,
        )?;

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                validate_info,
                None,
                actual_resources,
                Some(self.tx_type.clone()),
            ),
        )
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Internal Account Functions
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    pub fn get_execution_context(&self, n_steps: u64) -> TransactionExecutionContext {
        TransactionExecutionContext::new(
            self.sender_address.clone(),
            self.hash_value.clone(),
            self.signature.clone(),
            self.max_fee,
            self.nonce.clone(),
            n_steps,
            self.version,
        )
    }

    pub fn run_validate_entrypoint(
        &self,
        state: &mut CachedState<InMemoryStateReader>,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: StarknetGeneralConfig,
    ) -> Result<Option<CallInfo>, ExecutionError> {
        if self.version > u64::pow(2, 128) {
            return Ok(None);
        }

        let calldata = self
            .validate_entrypoint_calldata()
            .into_iter()
            .map(|val| val.into())
            .collect();

        let call = ExecutionEntryPoint::new(
            self.account_contract_address(),
            calldata,
            self.validate_entry_point_selector.clone(),
            Address(Felt::zero()),
            EntryPointType::External,
            None,
            None,
        );

        let call_info = call.execute(
            state,
            &general_config,
            resources_manager,
            &self.get_execution_context(general_config.invoke_tx_max_n_steps),
        )?;

        verify_no_calls_to_other_contracts(&call_info)
            .map_err(|_| ExecutionError::UnauthorizedActionOnValidate)?;

        Ok(Some(call_info))
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Calculates and charges the actual fee.
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    pub fn charge_fee(
        &self,
        state: &mut CachedState<InMemoryStateReader>,
        resources: HashMap<String, Felt>,
        general_config: StarknetGeneralConfig,
    ) -> FeeInfo {
        if self.max_fee.is_zero() {
            return (None, 0);
        }

        todo!()
    }

    fn handle_nonce(
        &self,
        state: &mut CachedState<InMemoryStateReader>,
    ) -> Result<(), TransactionError> {
        if self.version > u64::pow(2, 128) {
            return Err(TransactionError::StarknetError(
                "Don't handle nonce for version 0".to_string(),
            ));
        }

        let contract_address = self.account_contract_address();
        let current_nonce = state.get_nonce_at(&contract_address)?.to_owned();
        if current_nonce != self.nonce {
            return Err(TransactionError::InvalidTransactionNonce(
                current_nonce.to_string(),
                self.nonce.clone().to_string(),
            ));
        }

        state.increment_nonce(&contract_address)?;

        Ok(())
    }

    pub fn apply_specific_sequential_changes(
        &self,
        state: &mut CachedState<InMemoryStateReader>,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, Felt>,
    ) -> Result<FeeInfo, TransactionError> {
        self.handle_nonce(state)?;

        Ok(self.charge_fee(state, actual_resources, general_config))
    }
}

// ------------------------------------------------------------
//                   Trait implementation
// ------------------------------------------------------------
