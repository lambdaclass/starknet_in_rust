use super::{
    error::TransactionError,
    fee::{calculate_tx_fee, execute_fee_transfer},
    state_objects::FeeInfo,
};
use crate::{
    business_logic::{
        execution::{
            error::ExecutionError,
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, CallType, TransactionExecutionContext, TransactionExecutionInfo},
        },
        fact_state::{
            contract_state::StateSelector, in_memory_state_reader::InMemoryStateReader,
            state::ExecutionResourcesManager,
        },
        state::{
            cached_state::CachedState,
            state_api::{State, StateReader},
        },
    },
    core::{
        contract_address::starknet_contract_address::compute_class_hash,
        errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError},
        transaction_hash::starknet_transaction_hash::{
            calculate_declare_transaction_hash, calculate_deploy_account_transaction_hash,
            calculate_deploy_transaction_hash,
        },
    },
    definitions::{
        constants::{CONSTRUCTOR_ENTRY_POINT_SELECTOR, VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR},
        general_config::{StarknetChainId, StarknetGeneralConfig},
        transaction_type::TransactionType,
    },
    hash_utils::calculate_contract_address,
    services::api::contract_class::{ContractClass, EntryPointType},
    starkware_utils::starkware_errors::StarkwareError,
    utils::{calculate_tx_resources, felt_to_hash, verify_no_calls_to_other_contracts, Address},
};
use felt::{felt_str, Felt};
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

    pub fn _apply_specific_concurrent_changes<S: State + StateReader + Clone>(
        &self,
        mut state: CachedState<S>,
        _general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, StarkwareError> {
        state.deploy_contract(self.contract_address.clone(), self.contract_hash)?;
        let class_hash: [u8; 32] = self.contract_hash;
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

    pub fn handle_empty_constructor<T: State + StateReader>(
        &self,
        state: &mut T,
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
            state.count_actual_storage_changes(),
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

    pub fn invoke_constructor<S: State + StateReader + Clone>(
        &self,
        _state: CachedState<S>,
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
    #![allow(unused)] // TODO: delete once used
    pub fn new(
        contract_class: ContractClass,
        chain_id: Felt,
        sender_address: Address,
        max_fee: u64,
        version: u64,
        signature: Vec<Felt>,
        nonce: Felt,
    ) -> Result<Self, TransactionError> {
        let hash = compute_class_hash(&contract_class)?;

        let class_hash = felt_to_hash(&hash);

        let hash_value = calculate_declare_transaction_hash(
            contract_class,
            chain_id,
            &sender_address,
            max_fee,
            version,
            nonce.clone(),
        )?;

        // Value generated from get_selector_from_name(VALIDATE_DECLARE_ENTRY_POINT_NAME)
        let validate_entry_point_selector = felt_str!(
            "1148189391774113786911959041662034419554430000171893651982484995704491697075"
        );

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

        internal_declare.verify_version()?;

        Ok(internal_declare)
    }

    pub fn account_contract_address(&self) -> Address {
        self.sender_address.clone()
    }

    pub fn get_calldata(&self) -> Vec<Felt> {
        let bytes = Felt::from_bytes_be(&self.class_hash);
        Vec::from([bytes])
    }

    pub fn verify_version(&self) -> Result<(), TransactionError> {
        // no need to check if its lesser than 0 because it is an usize
        if self.version > 0x8000_0000_0000_0000 {
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

    pub fn apply_specific_concurrent_changes<S: Default + State + StateReader>(
        &self,
        state: &mut S,
        general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, ExecutionError> {
        self.verify_version()?;
        // validate transaction
        let mut resources_manager = ExecutionResourcesManager::default();

        let validate_info =
            self.run_validate_entrypoint(state, &mut resources_manager, general_config)?;

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &vec![validate_info.clone()],
            TransactionType::Declare,
            state.count_actual_storage_changes(),
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

    pub fn run_validate_entrypoint<S: Default + State + StateReader>(
        &self,
        state: &mut S,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: StarknetGeneralConfig,
    ) -> Result<Option<CallInfo>, ExecutionError> {
        if self.version > 0x8000_0000_0000_0000 {
            return Ok(None);
        }

        let calldata = self.get_calldata();

        let entry_point = ExecutionEntryPoint::new(
            self.account_contract_address(),
            calldata,
            self.validate_entry_point_selector.clone(),
            Address(Felt::zero()),
            EntryPointType::External,
            Some(CallType::Delegate),
            Some(self.class_hash),
        );

        let call_info = entry_point.execute(
            state,
            &general_config,
            resources_manager,
            &self.get_execution_context(general_config.invoke_tx_max_n_steps),
        )?;

        verify_no_calls_to_other_contracts(&call_info)
            .map_err(|_| ExecutionError::UnauthorizedActionOnValidate)?;

        Ok(Some(call_info))
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Calculates and charges the actual fee.
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    pub fn charge_fee(
        &self,
        state: &mut CachedState<InMemoryStateReader>,
        resources: HashMap<String, Felt>,
        general_config: StarknetGeneralConfig,
    ) -> Result<FeeInfo, TransactionError> {
        if self.max_fee.is_zero() {
            return Ok((None, 0));
        }

        let actual_fee = calculate_tx_fee(
            resources,
            general_config.starknet_os_config.gas_price,
            &general_config,
        )?;

        let tx_context = self.get_execution_context(general_config.invoke_tx_max_n_steps);
        let fee_transfer_info =
            execute_fee_transfer(state, general_config, tx_context, actual_fee)?;

        Ok((Some(fee_transfer_info), actual_fee))
    }

    fn handle_nonce(
        &self,
        state: &mut CachedState<InMemoryStateReader>,
    ) -> Result<(), TransactionError> {
        if self.version > 0x8000_0000_0000_0000 {
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

        self.charge_fee(state, actual_resources, general_config)
    }
}

#[derive(Clone, Debug)]
pub struct InternalDeployAccount {
    contract_address: Address,
    contract_address_salt: Address,
    class_hash: [u8; 32],
    constructor_calldata: Vec<Felt>,
    version: u64,
    nonce: u64,
    max_fee: u64,
    signature: Vec<Felt>,
    chain_id: StarknetChainId,
}

impl InternalDeployAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_hash: [u8; 32],
        max_fee: u64,
        version: u64,
        nonce: u64,
        constructor_calldata: Vec<Felt>,
        signature: Vec<Felt>,
        contract_address_salt: Address,
        chain_id: StarknetChainId,
    ) -> Result<Self, SyscallHandlerError> {
        let contract_address = calculate_contract_address(
            &contract_address_salt,
            &Felt::from_bytes_be(&class_hash),
            &constructor_calldata,
            Address(Felt::zero()),
        )?;

        Ok(Self {
            contract_address: Address(contract_address),
            contract_address_salt,
            class_hash,
            constructor_calldata,
            version,
            nonce,
            max_fee,
            signature,
            chain_id,
        })
    }

    pub fn get_state_selector(&self, _general_config: StarknetGeneralConfig) -> StateSelector {
        StateSelector {
            contract_addresses: vec![self.contract_address.clone()],
            class_hashes: vec![self.class_hash],
        }
    }

    fn _apply_specific_concurrent_changes<S>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, StateError>
    where
        S: Default + State + StateReader,
    {
        let contract_class = state.get_contract_class(&self.class_hash)?;

        state.deploy_contract(self.contract_address.clone(), self.class_hash)?;

        let mut resources_manager = ExecutionResourcesManager::default();
        let constructor_call_info = self
            .handle_constructor(
                contract_class,
                state,
                general_config,
                &mut resources_manager,
            )
            .map_err::<StateError, _>(|_| todo!())?;

        let validate_info = self
            .run_validate_entrypoint(state, &mut resources_manager, general_config)
            .map_err::<StateError, _>(|_| todo!())?;

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(constructor_call_info.clone()), validate_info.clone()],
            TransactionType::DeployAccount,
            state.count_actual_storage_changes(),
            None,
        )
        .map_err::<StateError, _>(|_| todo!())?;

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                validate_info,
                Some(constructor_call_info),
                actual_resources,
                Some(TransactionType::DeployAccount),
            ),
        )
    }

    pub fn handle_constructor<S>(
        &self,
        contract_class: ContractClass,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
        resources_manager: &mut ExecutionResourcesManager,
    ) -> Result<CallInfo, ExecutionError>
    where
        S: Default + State + StateReader,
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
        S: Default + State + StateReader,
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
                Felt::from_bytes_be(&self.class_hash),
                &self.constructor_calldata,
                self.max_fee,
                self.nonce,
                self.contract_address_salt.0.clone(),
                self.chain_id.to_felt(),
            )
            .unwrap(),
            self.signature.clone(),
            self.max_fee,
            self.nonce.into(),
            n_steps,
            self.version,
        )
    }

    pub fn run_validate_entrypoint<S>(
        &self,
        state: &mut S,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: &StarknetGeneralConfig,
    ) -> Result<Option<CallInfo>, ExecutionError>
    where
        S: Default + State + StateReader,
    {
        if self.version == 0 {
            return Ok(None);
        }

        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            [
                Felt::from_bytes_be(&self.class_hash),
                self.contract_address_salt.0.clone(),
            ]
            .into_iter()
            .chain(self.constructor_calldata.iter().cloned())
            .collect(),
            VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR.clone(),
            Address(Felt::zero()),
            EntryPointType::External,
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

        Ok(Some(call_info))
    }
}

// ---------------
//     Tests
// ---------------

#[cfg(test)]
mod tests {
    use felt::felt_str;
    use std::{collections::HashMap, path::PathBuf};

    use crate::{
        business_logic::{
            execution::objects::{CallInfo, CallType, TransactionExecutionInfo},
            fact_state::{
                contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
            },
            state::cached_state::CachedState,
        },
        core::contract_address::starknet_contract_address::compute_class_hash,
        definitions::{
            general_config::{StarknetChainId, StarknetGeneralConfig},
            transaction_type::TransactionType,
        },
        services::api::contract_class::{ContractClass, EntryPointType},
        starknet_storage::dict_storage::DictStorage,
        utils::{felt_to_hash, Address},
    };

    use super::InternalDeclare;

    #[test]
    fn test_internal_declare() {
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::try_from(path).unwrap();
        let chain_id = StarknetChainId::TestNet.to_felt();

        let internal_declare = InternalDeclare::new(
            contract_class.clone(),
            chain_id,
            Address(1.into()),
            0,
            0,
            Vec::new(),
            0.into(),
        )
        .unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------

        let class_hash = internal_declare.class_hash;
        contract_class_cache.insert(class_hash, contract_class.clone());

        // store sender_address
        let sender_address = Address(1.into());
        // this is not conceptually correct as the sender address would be an
        // Account contract (not the contract that we are currently declaring)
        // but for testing reasons its ok
        let contract_state = ContractState::new(class_hash, 3.into(), HashMap::new());

        contract_class_cache.insert(class_hash, contract_class.clone());

        let mut state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
        state_reader
            .contract_states
            .insert(sender_address, contract_state);
        //* ---------------------------------------
        //*    Create state with previous data
        //* ---------------------------------------

        let mut state = CachedState::new(state_reader, Some(contract_class_cache));

        //* ---------------------------------------
        //              Expected result
        //* ---------------------------------------

        // Value generated from selector _validate_declare_
        let entry_point_selector = Some(felt_str!(
            "1148189391774113786911959041662034419554430000171893651982484995704491697075"
        ));

        let class_hash_felt = compute_class_hash(&contract_class).unwrap();
        let expected_class_hash = felt_to_hash(&class_hash_felt);

        // Calldata is the class hash represented as a Felt
        let calldata = [felt_str!(
            "2901640178084440408246930713802824082113120028809962300981437495334608520882"
        )]
        .to_vec();

        let validate_info = Some(CallInfo {
            caller_address: Address(0.into()),
            call_type: Some(CallType::Delegate),
            contract_address: Address(1.into()),
            entry_point_selector,
            entry_point_type: Some(EntryPointType::External),
            calldata,
            class_hash: Some(expected_class_hash),
            ..Default::default()
        });

        let mut actual_resources = HashMap::new();
        actual_resources.insert("l1_gas_usage".to_string(), 0);
        let transaction_exec_info = TransactionExecutionInfo {
            validate_info,
            call_info: None,
            fee_transfer_info: None,
            actual_fee: 0,
            actual_resources,
            tx_type: Some(TransactionType::Declare),
        };

        // ---------------------
        //      Comparison
        // ---------------------
        assert_eq!(
            internal_declare
                .apply_specific_concurrent_changes(&mut state, StarknetGeneralConfig::default())
                .unwrap(),
            transaction_exec_info
        );
    }
}
