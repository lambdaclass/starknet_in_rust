use super::fee::{calculate_tx_fee, charge_fee};
use super::get_tx_version;
use super::{invoke_function::verify_no_calls_to_other_contracts, Transaction};
use crate::definitions::constants::VALIDATE_RETDATA;
use crate::execution::execution_entry_point::ExecutionResult;
use crate::execution::gas_usage::get_onchain_data_segment_length;
use crate::execution::os_usage::ESTIMATED_DEPLOY_ACCOUNT_STEPS;
use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;
use crate::services::eth_definitions::eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;
use crate::state::cached_state::CachedState;
use crate::state::state_api::StateChangesCount;
use crate::state::StateDiff;
use crate::{
    core::{
        errors::state_errors::StateError,
        transaction_hash::calculate_deploy_account_transaction_hash,
    },
    definitions::{
        block_context::BlockContext,
        constants::{
            CONSTRUCTOR_ENTRY_POINT_SELECTOR, INITIAL_GAS_COST,
            VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR,
        },
        transaction_type::TransactionType,
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, TransactionExecutionContext,
        TransactionExecutionInfo,
    },
    hash_utils::calculate_contract_address,
    services::api::{
        contract_class_errors::ContractClassError, contract_classes::compiled_class::CompiledClass,
    },
    state::{
        contract_class_cache::ContractClassCache,
        state_api::{State, StateReader},
        ExecutionResourcesManager,
    },
    syscalls::syscall_handler_errors::SyscallHandlerError,
    transaction::error::TransactionError,
    utils::{calculate_tx_resources, Address, ClassHash},
};
use cairo_vm::felt::Felt252;
use getset::Getters;
use num_traits::{One, Zero};
use std::collections::HashMap;
use std::fmt::Debug;

#[cfg(feature = "cairo-native")]
use {
    cairo_native::cache::ProgramCache,
    std::{cell::RefCell, rc::Rc},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSelector {
    pub contract_addresses: Vec<Address>,
    pub class_hashes: Vec<ClassHash>,
}

#[derive(Clone, Debug, Getters)]
pub struct DeployAccount {
    #[getset(get = "pub")]
    contract_address: Address,
    #[getset(get = "pub")]
    contract_address_salt: Felt252,
    #[getset(get = "pub")]
    class_hash: ClassHash,
    #[getset(get = "pub")]
    constructor_calldata: Vec<Felt252>,
    version: Felt252,
    nonce: Felt252,
    max_fee: u128,
    #[getset(get = "pub")]
    hash_value: Felt252,
    #[getset(get = "pub")]
    signature: Vec<Felt252>,
    skip_validate: bool,
    skip_execute: bool,
    skip_fee_transfer: bool,
    skip_nonce_check: bool,
}

impl DeployAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_hash: ClassHash,
        max_fee: u128,
        version: Felt252,
        nonce: Felt252,
        constructor_calldata: Vec<Felt252>,
        signature: Vec<Felt252>,
        contract_address_salt: Felt252,
        chain_id: Felt252,
    ) -> Result<Self, SyscallHandlerError> {
        let version = get_tx_version(version);
        let contract_address = Address(calculate_contract_address(
            &contract_address_salt,
            &Felt252::from_bytes_be(class_hash.to_bytes_be()),
            &constructor_calldata,
            Address(Felt252::zero()),
        )?);

        let hash_value = calculate_deploy_account_transaction_hash(
            version.clone(),
            &contract_address,
            Felt252::from_bytes_be(class_hash.to_bytes_be()),
            &constructor_calldata,
            max_fee,
            nonce.clone(),
            contract_address_salt.clone(),
            chain_id,
        )?;

        Ok(Self {
            contract_address,
            contract_address_salt,
            class_hash,
            constructor_calldata,
            version,
            nonce,
            max_fee,
            hash_value,
            signature,
            skip_execute: false,
            skip_validate: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_tx_hash(
        class_hash: ClassHash,
        max_fee: u128,
        version: Felt252,
        nonce: Felt252,
        constructor_calldata: Vec<Felt252>,
        signature: Vec<Felt252>,
        contract_address_salt: Felt252,
        hash_value: Felt252,
    ) -> Result<Self, SyscallHandlerError> {
        let version = get_tx_version(version);
        let contract_address = Address(calculate_contract_address(
            &contract_address_salt,
            &Felt252::from_bytes_be(class_hash.to_bytes_be()),
            &constructor_calldata,
            Address(Felt252::zero()),
        )?);

        Ok(Self {
            contract_address,
            contract_address_salt,
            class_hash,
            constructor_calldata,
            version,
            nonce,
            max_fee,
            hash_value,
            signature,
            skip_execute: false,
            skip_validate: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        })
    }

    pub fn get_state_selector(&self, _block_context: BlockContext) -> StateSelector {
        StateSelector {
            contract_addresses: vec![self.contract_address.clone()],
            class_hashes: vec![self.class_hash],
        }
    }

    #[tracing::instrument(level = "debug", ret, err, skip(self, state, block_context, program_cache), fields(
        tx_type = ?TransactionType::DeployAccount,
        self.version = ?self.version,
        self.class_hash = ?self.class_hash,
        self.hash_value = ?self.hash_value,
        self.contract_address = ?self.contract_address,
        self.contract_address_salt = ?self.contract_address_salt,
        self.nonce = ?self.nonce,
    ))]
    pub fn execute<S: StateReader, C: ContractClassCache>(
        &self,
        state: &mut CachedState<S, C>,
        block_context: &BlockContext,
        #[cfg(feature = "cairo-native")] program_cache: Option<
            Rc<RefCell<ProgramCache<'_, ClassHash>>>,
        >,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        if self.version != Felt252::one() {
            return Err(TransactionError::UnsupportedTxVersion(
                "DeployAccount".to_string(),
                self.version.clone(),
                vec![1],
            ));
        }

        if !self.skip_fee_transfer {
            self.check_fee_balance(state, block_context)?;
        }

        self.handle_nonce(state)?;

        let mut transactional_state = state.create_transactional()?;
        let mut tx_exec_info = self.apply(
            &mut transactional_state,
            block_context,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
        )?;

        let actual_fee = calculate_tx_fee(
            &tx_exec_info.actual_resources,
            block_context.starknet_os_config.gas_price,
            block_context,
        )?;

        if let Some(revert_error) = tx_exec_info.revert_error.clone() {
            // execution error
            tx_exec_info = tx_exec_info.to_revert_error(&revert_error);
        } else if actual_fee > self.max_fee {
            // max_fee exceeded
            tx_exec_info = tx_exec_info.to_revert_error(
                format!(
                    "Calculated fee ({}) exceeds max fee ({})",
                    actual_fee, self.max_fee
                )
                .as_str(),
            );
        } else {
            state
                .apply_state_update(&StateDiff::from_cached_state(transactional_state.cache())?)?;
        }

        let mut tx_execution_context =
            self.get_execution_context(block_context.invoke_tx_max_n_steps);
        let (fee_transfer_info, actual_fee) = charge_fee(
            state,
            &tx_exec_info.actual_resources,
            block_context,
            self.max_fee,
            &mut tx_execution_context,
            self.skip_fee_transfer,
            #[cfg(feature = "cairo-native")]
            program_cache,
        )?;

        tx_exec_info.set_fee_info(actual_fee, fee_transfer_info);

        Ok(tx_exec_info)
    }

    fn constructor_entry_points_empty(
        &self,
        contract_class: CompiledClass,
    ) -> Result<bool, StateError> {
        Ok(match contract_class {
            CompiledClass::Deprecated(class) => class
                .entry_points_by_type
                .get(&EntryPointType::Constructor)
                .ok_or(ContractClassError::NoneEntryPointType)?
                .is_empty(),
            CompiledClass::Casm { casm: class, .. } => {
                class.entry_points_by_type.constructor.is_empty()
            }
        })
    }

    /// Execute a call to the cairo-vm using the accounts_validation.cairo contract to validate
    /// the contract that is being declared. Then it returns the transaction execution info of the run.
    fn apply<S: StateReader, C: ContractClassCache>(
        &self,
        state: &mut CachedState<S, C>,
        block_context: &BlockContext,
        #[cfg(feature = "cairo-native")] program_cache: Option<
            Rc<RefCell<ProgramCache<'_, ClassHash>>>,
        >,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let contract_class = state.get_contract_class(&self.class_hash)?;

        state.deploy_contract(self.contract_address.clone(), self.class_hash)?;

        let mut resources_manager = ExecutionResourcesManager::default();
        let constructor_call_info = self.handle_constructor(
            contract_class,
            state,
            block_context,
            &mut resources_manager,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
        )?;

        let validate_info = if self.skip_validate {
            None
        } else {
            self.run_validate_entrypoint(
                state,
                block_context,
                &mut resources_manager,
                #[cfg(feature = "cairo-native")]
                program_cache,
            )?
        };

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(constructor_call_info.clone()), validate_info.clone()],
            TransactionType::DeployAccount,
            state.count_actual_state_changes(Some((
                &block_context.starknet_os_config.fee_token_address,
                &self.contract_address,
            )))?,
            None,
            0,
        )
        .map_err::<TransactionError, _>(|_| TransactionError::ResourcesCalculation)?;

        Ok(TransactionExecutionInfo::new_without_fee_info(
            validate_info,
            Some(constructor_call_info),
            None,
            actual_resources,
            Some(TransactionType::DeployAccount),
        ))
    }

    pub fn handle_constructor<S: StateReader, C: ContractClassCache>(
        &self,
        contract_class: CompiledClass,
        state: &mut CachedState<S, C>,
        block_context: &BlockContext,
        resources_manager: &mut ExecutionResourcesManager,
        #[cfg(feature = "cairo-native")] program_cache: Option<
            Rc<RefCell<ProgramCache<'_, ClassHash>>>,
        >,
    ) -> Result<CallInfo, TransactionError> {
        if self.constructor_entry_points_empty(contract_class)? {
            if !self.constructor_calldata.is_empty() {
                return Err(TransactionError::EmptyConstructorCalldata);
            }

            Ok(CallInfo::empty_constructor_call(
                self.contract_address.clone(),
                Address(Felt252::zero()),
                Some(self.class_hash),
            ))
        } else {
            self.run_constructor_entrypoint(
                state,
                block_context,
                resources_manager,
                #[cfg(feature = "cairo-native")]
                program_cache,
            )
        }
    }

    fn handle_nonce<S: State + StateReader>(&self, state: &mut S) -> Result<(), TransactionError> {
        if self.version.is_zero() {
            return Ok(());
        }

        // In blockifier, get_nonce_at returns zero if no entry is found.
        let current_nonce = state.get_nonce_at(&self.contract_address)?;
        if current_nonce != self.nonce && !self.skip_nonce_check {
            return Err(TransactionError::InvalidTransactionNonce(
                current_nonce.to_string(),
                self.nonce.to_string(),
            ));
        }
        state.increment_nonce(&self.contract_address)?;
        Ok(())
    }

    fn check_fee_balance<S: State + StateReader>(
        &self,
        state: &mut S,
        block_context: &BlockContext,
    ) -> Result<(), TransactionError> {
        if self.max_fee.is_zero() {
            return Ok(());
        }
        let minimal_fee = self.estimate_minimal_fee(block_context)?;
        // Check max fee is at least the estimated constant overhead.
        if self.max_fee < minimal_fee {
            return Err(TransactionError::MaxFeeTooLow(self.max_fee, minimal_fee));
        }
        // Check that the current balance is high enough to cover the max_fee
        let (balance_low, balance_high) =
            state.get_fee_token_balance(block_context, self.contract_address())?;
        // The fee is at most 128 bits, while balance is 256 bits (split into two 128 bit words).
        if balance_high.is_zero() && balance_low < Felt252::from(self.max_fee) {
            return Err(TransactionError::MaxFeeExceedsBalance(
                self.max_fee,
                balance_low,
                balance_high,
            ));
        }
        Ok(())
    }

    fn estimate_minimal_fee(&self, block_context: &BlockContext) -> Result<u128, TransactionError> {
        let n_estimated_steps = ESTIMATED_DEPLOY_ACCOUNT_STEPS;
        let onchain_data_length = get_onchain_data_segment_length(&StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 1,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        });
        let resources = HashMap::from([
            (
                "l1_gas_usage".to_string(),
                onchain_data_length * SHARP_GAS_PER_MEMORY_WORD,
            ),
            ("n_steps".to_string(), n_estimated_steps),
        ]);
        calculate_tx_fee(
            &resources,
            block_context.starknet_os_config.gas_price,
            block_context,
        )
    }

    pub fn run_constructor_entrypoint<S: StateReader, C: ContractClassCache>(
        &self,
        state: &mut CachedState<S, C>,
        block_context: &BlockContext,
        resources_manager: &mut ExecutionResourcesManager,
        #[cfg(feature = "cairo-native")] program_cache: Option<
            Rc<RefCell<ProgramCache<'_, ClassHash>>>,
        >,
    ) -> Result<CallInfo, TransactionError> {
        let entry_point = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.constructor_calldata.clone(),
            CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone(),
            Address(Felt252::zero()),
            EntryPointType::Constructor,
            None,
            None,
            INITIAL_GAS_COST,
        );

        let ExecutionResult { call_info, .. } = if self.skip_execute {
            ExecutionResult::default()
        } else {
            entry_point.execute(
                state,
                block_context,
                resources_manager,
                &mut self.get_execution_context(block_context.validate_max_n_steps),
                false,
                block_context.validate_max_n_steps,
                #[cfg(feature = "cairo-native")]
                program_cache,
            )?
        };

        let call_info = verify_no_calls_to_other_contracts(&call_info)
            .map_err(|_| TransactionError::InvalidContractCall)?;
        Ok(call_info)
    }

    pub fn get_execution_context(&self, n_steps: u64) -> TransactionExecutionContext {
        TransactionExecutionContext::new(
            self.contract_address.clone(),
            self.hash_value.clone(),
            self.signature.clone(),
            self.max_fee,
            self.nonce.clone(),
            n_steps,
            self.version.clone(),
        )
    }

    pub fn run_validate_entrypoint<S: StateReader, C: ContractClassCache>(
        &self,
        state: &mut CachedState<S, C>,
        block_context: &BlockContext,
        resources_manager: &mut ExecutionResourcesManager,
        #[cfg(feature = "cairo-native")] program_cache: Option<
            Rc<RefCell<ProgramCache<'_, ClassHash>>>,
        >,
    ) -> Result<Option<CallInfo>, TransactionError> {
        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            [
                Felt252::from_bytes_be(self.class_hash.to_bytes_be()),
                self.contract_address_salt.clone(),
            ]
            .into_iter()
            .chain(self.constructor_calldata.iter().cloned())
            .collect(),
            VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR.clone(),
            Address(Felt252::zero()),
            EntryPointType::External,
            None,
            None,
            INITIAL_GAS_COST,
        );

        let ExecutionResult { call_info, .. } = if self.skip_execute {
            ExecutionResult::default()
        } else {
            call.execute(
                state,
                block_context,
                resources_manager,
                &mut self.get_execution_context(block_context.validate_max_n_steps),
                false,
                block_context.validate_max_n_steps,
                #[cfg(feature = "cairo-native")]
                program_cache,
            )?
        };

        // Validate the return data
        let class_hash = state.get_class_hash_at(&self.contract_address)?;
        let contract_class = state
            .get_contract_class(&class_hash)
            .map_err(|_| TransactionError::MissingCompiledClass)?;
        if matches!(
            contract_class,
            CompiledClass::Casm {
                sierra: Some(_),
                ..
            }
        ) {
            // The account contract class is a Cairo 1.0 contract; the `validate` entry point should
            // return `VALID`.
            if !call_info
                .as_ref()
                .map(|ci| ci.retdata == vec![VALIDATE_RETDATA.clone()])
                .unwrap_or_default()
            {
                return Err(TransactionError::WrongValidateRetdata);
            }
        }

        verify_no_calls_to_other_contracts(&call_info)
            .map_err(|_| TransactionError::InvalidContractCall)?;

        Ok(call_info)
    }

    pub fn create_for_simulation(
        &self,
        skip_validate: bool,
        skip_execute: bool,
        skip_fee_transfer: bool,
        ignore_max_fee: bool,
        skip_nonce_check: bool,
    ) -> Transaction {
        let tx = DeployAccount {
            skip_validate,
            skip_execute,
            skip_fee_transfer,
            max_fee: if ignore_max_fee {
                u128::MAX
            } else {
                self.max_fee
            },
            skip_nonce_check,
            ..self.clone()
        };

        Transaction::DeployAccount(tx)
    }

    pub fn from_sn_api_transaction(
        value: starknet_api::transaction::DeployAccountTransaction,
        chain_id: Felt252,
    ) -> Result<Self, SyscallHandlerError> {
        let max_fee = value.max_fee.0;
        let version = Felt252::from_bytes_be(value.version.0.bytes());
        let nonce = Felt252::from_bytes_be(value.nonce.0.bytes());
        let class_hash: ClassHash = ClassHash(value.class_hash.0.bytes().try_into().unwrap());
        let contract_address_salt = Felt252::from_bytes_be(value.contract_address_salt.0.bytes());

        let signature = value
            .signature
            .0
            .iter()
            .map(|f| Felt252::from_bytes_be(f.bytes()))
            .collect();
        let constructor_calldata = value
            .constructor_calldata
            .0
            .as_ref()
            .iter()
            .map(|f| Felt252::from_bytes_be(f.bytes()))
            .collect();

        DeployAccount::new(
            class_hash,
            max_fee,
            version,
            nonce,
            constructor_calldata,
            signature,
            contract_address_salt,
            chain_id,
        )
    }
}

// ----------------------------------
//      Try from starknet api
// ----------------------------------

impl TryFrom<starknet_api::transaction::DeployAccountTransaction> for DeployAccount {
    type Error = SyscallHandlerError;

    fn try_from(
        value: starknet_api::transaction::DeployAccountTransaction,
    ) -> Result<Self, SyscallHandlerError> {
        let max_fee = value.max_fee.0;
        let version = Felt252::from_bytes_be(value.version.0.bytes());
        let nonce = Felt252::from_bytes_be(value.nonce.0.bytes());
        let class_hash: ClassHash = ClassHash(value.class_hash.0.bytes().try_into().unwrap());
        let contract_address_salt = Felt252::from_bytes_be(value.contract_address_salt.0.bytes());

        let signature = value
            .signature
            .0
            .iter()
            .map(|f| Felt252::from_bytes_be(f.bytes()))
            .collect();
        let constructor_calldata = value
            .constructor_calldata
            .0
            .as_ref()
            .iter()
            .map(|f| Felt252::from_bytes_be(f.bytes()))
            .collect();

        let chain_id = Felt252::zero();

        DeployAccount::new(
            class_hash,
            max_fee,
            version,
            nonce,
            constructor_calldata,
            signature,
            contract_address_salt,
            chain_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{contract_address::compute_deprecated_class_hash, errors::state_errors::StateError},
        definitions::block_context::StarknetChainId,
        services::api::contract_classes::deprecated_contract_class::ContractClass,
        state::in_memory_state_reader::InMemoryStateReader,
        state::{cached_state::CachedState, contract_class_cache::PermanentContractClassCache},
        utils::felt_to_hash,
    };
    use std::{path::PathBuf, sync::Arc};

    #[test]
    fn get_state_selector() {
        let path = PathBuf::from("starknet_programs/constructor.json");
        let contract = ContractClass::from_path(path).unwrap();

        let hash = compute_deprecated_class_hash(&contract).unwrap();
        let class_hash = felt_to_hash(&hash);

        let block_context = BlockContext::default();
        let mut _state = CachedState::new(
            Arc::new(InMemoryStateReader::default()),
            Arc::new(PermanentContractClassCache::default()),
        );

        let internal_deploy = DeployAccount::new(
            class_hash,
            0,
            0.into(),
            0.into(),
            vec![10.into()],
            Vec::new(),
            0.into(),
            StarknetChainId::TestNet2.to_felt(),
        )
        .unwrap();

        let state_selector = internal_deploy.get_state_selector(block_context);

        assert_eq!(
            state_selector.contract_addresses,
            vec![internal_deploy.contract_address]
        );
        assert_eq!(state_selector.class_hashes, vec![class_hash]);
    }

    #[test]
    fn deploy_account_twice_should_fail() {
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract = ContractClass::from_path(path).unwrap();

        let hash = compute_deprecated_class_hash(&contract).unwrap();
        let class_hash = felt_to_hash(&hash);

        let block_context = BlockContext::default();
        let mut state = CachedState::new(
            Arc::new(InMemoryStateReader::default()),
            Arc::new(PermanentContractClassCache::default()),
        );

        let internal_deploy = DeployAccount::new(
            class_hash,
            0,
            1.into(),
            0.into(),
            vec![],
            Vec::new(),
            0.into(),
            StarknetChainId::TestNet2.to_felt(),
        )
        .unwrap();

        let internal_deploy_error = DeployAccount::new(
            class_hash,
            0,
            1.into(),
            1.into(),
            vec![],
            Vec::new(),
            0.into(),
            StarknetChainId::TestNet2.to_felt(),
        )
        .unwrap();

        let class_hash = internal_deploy.class_hash();
        state
            .set_contract_class(class_hash, &CompiledClass::Deprecated(Arc::new(contract)))
            .unwrap();
        internal_deploy
            .execute(
                &mut state,
                &block_context,
                #[cfg(feature = "cairo-native")]
                None,
            )
            .unwrap();
        assert_matches!(
            internal_deploy_error
                .execute(
                    &mut state,
                    &block_context,
                    #[cfg(feature = "cairo-native")]
                    None,
                )
                .unwrap_err(),
            TransactionError::State(StateError::ContractAddressUnavailable(..))
        )
    }

    #[test]
    #[should_panic]
    // Should panic at no calldata for constructor. Error managment not implemented yet.
    fn deploy_account_constructor_should_fail() {
        let path = PathBuf::from("starknet_programs/constructor.json");
        let contract = ContractClass::from_path(path).unwrap();

        let hash = compute_deprecated_class_hash(&contract).unwrap();
        let class_hash = felt_to_hash(&hash);

        let block_context = BlockContext::default();
        let mut state = CachedState::new(
            Arc::new(InMemoryStateReader::default()),
            Arc::new(PermanentContractClassCache::default()),
        );

        let internal_deploy = DeployAccount::new(
            class_hash,
            0,
            0.into(),
            0.into(),
            Vec::new(),
            Vec::new(),
            0.into(),
            StarknetChainId::TestNet2.to_felt(),
        )
        .unwrap();

        let class_hash = internal_deploy.class_hash();
        state
            .set_contract_class(class_hash, &CompiledClass::Deprecated(Arc::new(contract)))
            .unwrap();
        internal_deploy
            .execute(
                &mut state,
                &block_context,
                #[cfg(feature = "cairo-native")]
                None,
            )
            .unwrap();
    }

    #[test]
    fn deploy_account_wrong_version() {
        let chain_id = StarknetChainId::TestNet.to_felt();

        // declare tx
        let internal_declare = DeployAccount::new(
            ClassHash([2; 32]),
            9000,
            2.into(),
            Felt252::zero(),
            vec![],
            vec![],
            Felt252::one(),
            chain_id,
        )
        .unwrap();
        let result = internal_declare.execute(
            &mut CachedState::<InMemoryStateReader, PermanentContractClassCache>::default(),
            &BlockContext::default(),
            #[cfg(feature = "cairo-native")]
            None,
        );

        assert_matches!(
        result,
        Err(TransactionError::UnsupportedTxVersion(tx, ver, supp))
        if tx == "DeployAccount" && ver == 2.into() && supp == vec![1]);
    }
}
