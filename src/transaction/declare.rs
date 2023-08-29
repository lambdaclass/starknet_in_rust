use crate::definitions::constants::QUERY_VERSION_BASE;
use crate::execution::execution_entry_point::ExecutionResult;
use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;
use crate::state::cached_state::CachedState;
use crate::{
    core::{
        contract_address::compute_deprecated_class_hash,
        transaction_hash::calculate_declare_transaction_hash,
    },
    definitions::{
        block_context::BlockContext, constants::VALIDATE_DECLARE_ENTRY_POINT_SELECTOR,
        transaction_type::TransactionType,
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, TransactionExecutionContext,
        TransactionExecutionInfo,
    },
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    state::state_api::{State, StateReader},
    state::ExecutionResourcesManager,
    transaction::error::TransactionError,
    utils::{
        calculate_tx_resources, felt_to_hash, verify_no_calls_to_other_contracts, Address,
        ClassHash,
    },
};
use cairo_vm::felt::Felt252;
use num_traits::Zero;

use super::fee::charge_fee;
use super::{verify_version, Transaction};

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
///  Represents an internal transaction in the StarkNet network that is a declaration of a Cairo
///  contract class.
#[derive(Debug, Clone)]
pub struct Declare {
    pub class_hash: ClassHash,
    pub sender_address: Address,
    pub tx_type: TransactionType,
    pub validate_entry_point_selector: Felt252,
    pub version: Felt252,
    pub max_fee: u128,
    pub signature: Vec<Felt252>,
    pub nonce: Felt252,
    pub hash_value: Felt252,
    pub contract_class: ContractClass,
    pub skip_validate: bool,
    pub skip_execute: bool,
    pub skip_fee_transfer: bool,
}

// ------------------------------------------------------------
//                        Functions
// ------------------------------------------------------------
impl Declare {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_class: ContractClass,
        chain_id: Felt252,
        sender_address: Address,
        max_fee: u128,
        version: Felt252,
        signature: Vec<Felt252>,
        nonce: Felt252,
    ) -> Result<Self, TransactionError> {
        let hash = compute_deprecated_class_hash(&contract_class)?;
        let class_hash = felt_to_hash(&hash);

        let hash_value = calculate_declare_transaction_hash(
            &contract_class,
            chain_id,
            &sender_address,
            max_fee,
            version.clone(),
            nonce.clone(),
        )?;

        let validate_entry_point_selector = VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone();

        let internal_declare = Declare {
            class_hash,
            sender_address,
            tx_type: TransactionType::Declare,
            validate_entry_point_selector,
            version,
            max_fee,
            signature,
            nonce,
            hash_value,
            contract_class,
            skip_execute: false,
            skip_validate: false,
            skip_fee_transfer: false,
        };

        verify_version(
            &internal_declare.version,
            internal_declare.max_fee,
            &internal_declare.nonce,
            &internal_declare.signature,
        )?;

        Ok(internal_declare)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_tx_hash(
        contract_class: ContractClass,
        sender_address: Address,
        max_fee: u128,
        version: Felt252,
        signature: Vec<Felt252>,
        nonce: Felt252,
        hash_value: Felt252,
    ) -> Result<Self, TransactionError> {
        let hash = compute_deprecated_class_hash(&contract_class)?;
        let class_hash = felt_to_hash(&hash);

        let validate_entry_point_selector = VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone();

        let internal_declare = Declare {
            class_hash,
            sender_address,
            tx_type: TransactionType::Declare,
            validate_entry_point_selector,
            version,
            max_fee,
            signature,
            nonce,
            hash_value,
            contract_class,
            skip_execute: false,
            skip_validate: false,
            skip_fee_transfer: false,
        };

        verify_version(
            &internal_declare.version,
            internal_declare.max_fee,
            &internal_declare.nonce,
            &internal_declare.signature,
        )?;

        Ok(internal_declare)
    }

    pub fn get_calldata(&self) -> Vec<Felt252> {
        let bytes = Felt252::from_bytes_be(&self.class_hash);
        Vec::from([bytes])
    }

    /// Executes a call to the cairo-vm using the accounts_validation.cairo contract to validate
    /// the contract that is being declared. Then it returns the transaction execution info of the run.
    pub fn apply<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        block_context: &BlockContext,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        verify_version(&self.version, self.max_fee, &self.nonce, &self.signature)?;

        // validate transaction
        let mut resources_manager = ExecutionResourcesManager::default();
        let validate_info = if self.skip_validate {
            None
        } else {
            self.run_validate_entrypoint(state, &mut resources_manager, block_context)?
        };
        let changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &vec![validate_info.clone()],
            TransactionType::Declare,
            changes,
            None,
            0,
        )
        .map_err(|_| TransactionError::ResourcesCalculation)?;

        Ok(TransactionExecutionInfo::new_without_fee_info(
            validate_info,
            None,
            None,
            actual_resources,
            Some(self.tx_type),
        ))
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
            self.version.clone(),
            false,
        )
    }

    pub fn run_validate_entrypoint<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        resources_manager: &mut ExecutionResourcesManager,
        block_context: &BlockContext,
    ) -> Result<Option<CallInfo>, TransactionError> {
        if self.version.is_zero() || self.version == *QUERY_VERSION_BASE {
            return Ok(None);
        }

        let calldata = self.get_calldata();

        let entry_point = ExecutionEntryPoint::new(
            self.sender_address.clone(),
            calldata,
            self.validate_entry_point_selector.clone(),
            Address(Felt252::zero()),
            EntryPointType::External,
            None,
            None,
            0,
        );

        let ExecutionResult { call_info, .. } = entry_point.execute(
            state,
            block_context,
            resources_manager,
            &mut self.get_execution_context(block_context.invoke_tx_max_n_steps),
            false,
            block_context.validate_max_n_steps,
        )?;

        let call_info = call_info.ok_or(TransactionError::CallInfoIsNone)?;

        verify_no_calls_to_other_contracts(&call_info)
            .map_err(|_| TransactionError::UnauthorizedActionOnValidate)?;

        Ok(Some(call_info))
    }

    fn handle_nonce<S: State + StateReader>(&self, state: &mut S) -> Result<(), TransactionError> {
        if self.version.is_zero() || self.version == *QUERY_VERSION_BASE {
            return Ok(());
        }

        let contract_address = &self.sender_address;
        let current_nonce = state.get_nonce_at(contract_address)?;
        if current_nonce != self.nonce {
            return Err(TransactionError::InvalidTransactionNonce(
                current_nonce.to_string(),
                self.nonce.to_string(),
            ));
        }

        state.increment_nonce(contract_address)?;

        Ok(())
    }

    /// Calculates actual fee used by the transaction using the execution
    /// info returned by apply(), then updates the transaction execution info with the data of the fee.
    pub fn execute<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        block_context: &BlockContext,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        self.handle_nonce(state)?;
        let mut tx_exec_info = self.apply(state, block_context)?;

        let mut tx_execution_context =
            self.get_execution_context(block_context.invoke_tx_max_n_steps);
        let (fee_transfer_info, actual_fee) = charge_fee(
            state,
            &tx_exec_info.actual_resources,
            block_context,
            self.max_fee,
            &mut tx_execution_context,
            self.skip_fee_transfer,
        )?;

        state.set_contract_class(&self.class_hash, &self.contract_class)?;

        tx_exec_info.set_fee_info(actual_fee, fee_transfer_info);

        Ok(tx_exec_info)
    }

    pub(crate) fn create_for_simulation(
        &self,
        skip_validate: bool,
        skip_execute: bool,
        skip_fee_transfer: bool,
        ignore_max_fee: bool,
    ) -> Transaction {
        let tx = Declare {
            skip_validate,
            skip_execute,
            skip_fee_transfer,
            max_fee: if ignore_max_fee {
                u128::MAX
            } else {
                self.max_fee
            },
            ..self.clone()
        };

        Transaction::Declare(tx)
    }
}

// ---------------
//     Tests
// ---------------

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_vm::{
        felt::{felt_str, Felt252},
        vm::runners::cairo_runner::ExecutionResources,
    };
    use num_traits::{One, Zero};
    use std::{collections::HashMap, path::PathBuf, sync::Arc};

    use crate::{
        definitions::{
            block_context::{BlockContext, StarknetChainId},
            constants::VALIDATE_DECLARE_ENTRY_POINT_SELECTOR,
            transaction_type::TransactionType,
        },
        execution::CallType,
        services::api::contract_classes::deprecated_contract_class::ContractClass,
        state::cached_state::CachedState,
        state::in_memory_state_reader::InMemoryStateReader,
        utils::{felt_to_hash, Address},
    };

    use super::Declare;

    #[test]
    fn declare_fibonacci() {
        // accounts contract class must be stored before running declaration of fibonacci
        let contract_class =
            ContractClass::from_path("starknet_programs/account_without_validation.json").unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = hash.to_be_bytes();

        contract_class_cache.insert(class_hash, contract_class.clone());

        // store sender_address
        let sender_address = Address(1.into());
        // this is not conceptually correct as the sender address would be an
        // Account contract (not the contract that we are currently declaring)
        // but for testing reasons its ok

        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(sender_address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(sender_address, Felt252::new(1));

        let mut state = CachedState::new(Arc::new(state_reader))
            .set_contract_classes_cache(contract_class_cache);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // declare tx
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            1.into(),
            Vec::new(),
            Felt252::zero(),
        )
        .unwrap();

        //* ---------------------------------------
        //              Expected result
        //* ---------------------------------------

        // Value generated from selector _validate_declare_
        let entry_point_selector = Some(VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone());

        let class_hash_felt = compute_deprecated_class_hash(&contract_class).unwrap();
        let expected_class_hash = felt_to_hash(&class_hash_felt);

        // Calldata is the class hash represented as a Felt252
        let calldata = [felt_str!(
            "151449101692423517761547521693863750221386499114738230243355039033913267347"
        )]
        .to_vec();

        let validate_info = Some(CallInfo {
            caller_address: Address(0.into()),
            call_type: Some(CallType::Call),
            contract_address: Address(Felt252::one()),
            entry_point_selector,
            entry_point_type: Some(EntryPointType::External),
            calldata,
            class_hash: Some(expected_class_hash),
            execution_resources: ExecutionResources {
                n_steps: 12,
                ..Default::default()
            },
            ..Default::default()
        });

        let actual_resources = HashMap::from([
            ("n_steps".to_string(), 2715),
            ("l1_gas_usage".to_string(), 1224),
            ("range_check_builtin".to_string(), 63),
            ("pedersen_builtin".to_string(), 15),
        ]);
        let transaction_exec_info = TransactionExecutionInfo {
            validate_info,
            call_info: None,
            revert_error: None,
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
                .apply(&mut state, &BlockContext::default())
                .unwrap(),
            transaction_exec_info
        );
    }

    #[test]
    fn verify_version_zero_should_fail_max_fee() {
        // accounts contract class must be stored before running declaration of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::from_path(path).unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);

        contract_class_cache.insert(class_hash, contract_class);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();
        let max_fee = 1000;
        let version = 0.into();

        // Declare tx should fail because max_fee > 0 and version == 0
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            max_fee,
            version,
            Vec::new(),
            Felt252::from(max_fee),
        );

        // ---------------------
        //      Comparison
        // ---------------------
        assert!(internal_declare.is_err());
        assert_matches!(
            internal_declare.unwrap_err(),
            TransactionError::InvalidMaxFee
        );
    }

    #[test]
    fn verify_version_zero_should_fail_nonce() {
        // accounts contract class must be stored before running declaration of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::from_path(path).unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);

        contract_class_cache.insert(class_hash, contract_class);

        // store sender_address
        let sender_address = Address(1.into());
        // this is not conceptually correct as the sender address would be an
        // Account contract (not the contract that we are currently declaring)
        // but for testing reasons its ok

        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(sender_address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(sender_address, Felt252::new(1));

        let _state = CachedState::new(Arc::new(state_reader))
            .set_contract_classes_cache(contract_class_cache);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();
        let nonce = Felt252::from(148);
        let version = 0.into();

        // Declare tx should fail because nonce > 0 and version == 0
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            version,
            Vec::new(),
            nonce,
        );

        // ---------------------
        //      Comparison
        // ---------------------
        assert!(internal_declare.is_err());
        assert_matches!(
            internal_declare.unwrap_err(),
            TransactionError::InvalidNonce
        );
    }

    #[test]
    fn verify_signature_should_fail_not_empty_list() {
        // accounts contract class must be stored before running declaration of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::from_path(path).unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);

        contract_class_cache.insert(class_hash, contract_class);

        // store sender_address
        let sender_address = Address(1.into());
        // this is not conceptually correct as the sender address would be an
        // Account contract (not the contract that we are currently declaring)
        // but for testing reasons its ok

        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(sender_address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(sender_address, Felt252::new(1));

        let _state = CachedState::new(Arc::new(state_reader))
            .set_contract_classes_cache(contract_class_cache);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();
        let signature = vec![1.into(), 2.into()];

        // Declare tx should fail because signature is not empty
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            0.into(),
            signature,
            Felt252::zero(),
        );

        // ---------------------
        //      Comparison
        // ---------------------
        assert!(internal_declare.is_err());
        assert_matches!(
            internal_declare.unwrap_err(),
            TransactionError::InvalidSignature
        );
    }

    #[test]
    fn execute_class_already_declared_should_redeclare() {
        // accounts contract class must be stored before running declaration of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::from_path(path).unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);

        contract_class_cache.insert(class_hash, contract_class);

        // store sender_address
        let sender_address = Address(1.into());
        // this is not conceptually correct as the sender address would be an
        // Account contract (not the contract that we are currently declaring)
        // but for testing reasons its ok

        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(sender_address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(sender_address, Felt252::zero());

        let mut state = CachedState::new(Arc::new(state_reader))
            .set_contract_classes_cache(contract_class_cache);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // Declare same class twice
        let internal_declare = Declare::new(
            fib_contract_class.clone(),
            chain_id.clone(),
            Address(Felt252::one()),
            0,
            1.into(),
            Vec::new(),
            Felt252::zero(),
        )
        .unwrap();

        let second_internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            1.into(),
            Vec::new(),
            Felt252::one(),
        )
        .unwrap();

        internal_declare
            .execute(&mut state, &BlockContext::default())
            .unwrap();

        assert!(state.get_contract_class(&class_hash).is_ok());

        second_internal_declare
            .execute(&mut state, &BlockContext::default())
            .unwrap();

        assert!(state.get_contract_class(&class_hash).is_ok());
    }

    #[test]
    fn execute_transaction_twice_should_fail() {
        // accounts contract class must be stored before running declaration of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::from_path(path).unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);

        contract_class_cache.insert(class_hash, contract_class);

        // store sender_address
        let sender_address = Address(1.into());
        // this is not conceptually correct as the sender address would be an
        // Account contract (not the contract that we are currently declaring)
        // but for testing reasons its ok

        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(sender_address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(sender_address, Felt252::zero());

        let mut state = CachedState::new(Arc::new(state_reader))
            .set_contract_classes_cache(contract_class_cache);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // Declare same class twice
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            1.into(),
            Vec::new(),
            Felt252::zero(),
        )
        .unwrap();

        internal_declare
            .execute(&mut state, &BlockContext::default())
            .unwrap();

        let expected_error = internal_declare.execute(&mut state, &BlockContext::default());

        // ---------------------
        //      Comparison
        // ---------------------

        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::InvalidTransactionNonce(..)
        )
    }

    #[test]
    fn validate_transaction_should_fail() {
        // Instantiate CachedState
        let contract_class_cache = HashMap::new();

        let state_reader = Arc::new(InMemoryStateReader::default());

        let mut state =
            CachedState::new(state_reader).set_contract_classes_cache(contract_class_cache);

        // There are no account contracts in the state, so the transaction should fail
        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            1.into(),
            Vec::new(),
            Felt252::zero(),
        )
        .unwrap();

        let internal_declare_error = internal_declare.execute(&mut state, &BlockContext::default());

        assert!(internal_declare_error.is_err());
        assert_matches!(
            internal_declare_error.unwrap_err(),
            TransactionError::NotDeployedContract(..)
        );
    }

    #[test]
    fn execute_transaction_charge_fee_should_fail() {
        // accounts contract class must be stored before running declaration of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::from_path(path).unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);

        contract_class_cache.insert(class_hash, contract_class);

        // store sender_address
        let sender_address = Address(1.into());
        // this is not conceptually correct as the sender address would be an
        // Account contract (not the contract that we are currently declaring)
        // but for testing reasons its ok

        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(sender_address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(sender_address, Felt252::zero());

        let mut state = CachedState::new(Arc::new(state_reader))
            .set_contract_classes_cache(contract_class_cache);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // Use non-zero value so that the actual fee calculation is done
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            10,
            1.into(),
            Vec::new(),
            Felt252::zero(),
        )
        .unwrap();

        // We expect a fee transfer failure because the fee token contract is not set up
        assert_matches!(
            internal_declare.execute(&mut state, &BlockContext::default()),
            Err(TransactionError::FeeTransferError(_))
        );
    }
}
