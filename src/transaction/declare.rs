use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;
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
    transaction::{
        error::TransactionError,
        fee::{calculate_tx_fee, execute_fee_transfer, FeeInfo},
    },
    utils::{
        calculate_tx_resources, felt_to_hash, verify_no_calls_to_other_contracts, Address,
        ClassHash,
    },
};
use cairo_vm::felt::Felt252;
use num_traits::Zero;
use std::collections::HashMap;

use super::{handle_nonce, verify_version, Transaction};

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
        hash_value: Option<Felt252>,
    ) -> Result<Self, TransactionError> {
        let hash = compute_deprecated_class_hash(&contract_class)?;
        let class_hash = felt_to_hash(&hash);

        let hash_value = match hash_value {
            Some(hash) => hash,
            None => calculate_declare_transaction_hash(
                &contract_class,
                chain_id,
                &sender_address,
                max_fee,
                version.clone(),
                nonce.clone(),
            )?,
        };

        let validate_entry_point_selector = VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone();

        let declare = Declare {
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

        Ok(declare)
    }

    /// Executes a call to the cairo-vm using the accounts_validation.cairo contract to validate
    /// the contract that is being declared. Then it returns the transaction execution info of the run.
    fn validate<S: State + StateReader>(
        &self,
        state: &mut S,
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
        )?;

        handle_nonce(&self.nonce, &self.version, &self.sender_address, state)?;

        Ok(TransactionExecutionInfo::new_without_fee_info(
            validate_info,
            None,
            actual_resources,
            Some(self.tx_type),
        ))
    }

    pub fn get_execution_context(&self, n_steps: u64) -> TransactionExecutionContext {
        TransactionExecutionContext::new(
            self.sender_address.clone(),
            self.hash_value.clone(),
            self.signature.clone(),
            self.max_fee,
            self.nonce.clone(),
            n_steps,
            self.version.clone(),
        )
    }

    fn run_validate_entrypoint<S: State + StateReader>(
        &self,
        state: &mut S,
        resources_manager: &mut ExecutionResourcesManager,
        block_context: &BlockContext,
    ) -> Result<Option<CallInfo>, TransactionError> {
        if self.version.is_zero() {
            return Ok(None);
        }

        // the calldata for the validation entrypoint is just the class_hash
        let validate_calldata = vec![Felt252::from_bytes_be(&self.class_hash)];

        // create an entrypoint for executing the validation
        let entry_point = ExecutionEntryPoint::new(
            self.sender_address.clone(),
            validate_calldata,
            self.validate_entry_point_selector.clone(),
            Address(Felt252::zero()),
            EntryPointType::External,
            None,
            None,
            0,
        );

        let call_info = entry_point.execute(
            state,
            block_context,
            resources_manager,
            &mut self.get_execution_context(block_context.invoke_tx_max_n_steps),
            false,
        )?;

        verify_no_calls_to_other_contracts(&call_info)
            .map_err(|_| TransactionError::UnauthorizedActionOnValidate)?;

        Ok(Some(call_info))
    }

    /// Calculates and charges the actual fee.
    fn charge_fee<S: State + StateReader>(
        &self,
        state: &mut S,
        resources: &HashMap<String, usize>,
        block_context: &BlockContext,
    ) -> Result<FeeInfo, TransactionError> {
        if self.max_fee.is_zero() {
            return Ok((None, 0));
        }

        let actual_fee = calculate_tx_fee(
            resources,
            block_context.starknet_os_config.gas_price,
            block_context,
        )?;

        let mut tx_execution_context =
            self.get_execution_context(block_context.invoke_tx_max_n_steps);
        let fee_transfer_info = if self.skip_fee_transfer {
            None
        } else {
            Some(execute_fee_transfer(
                state,
                block_context,
                &mut tx_execution_context,
                actual_fee,
            )?)
        };
        Ok((fee_transfer_info, actual_fee))
    }

    /// Calculates actual fee used by the transaction using the execution
    /// info returned by apply(), then updates the transaction execution info with the data of the fee.
    pub fn execute<S: State + StateReader>(
        &self,
        state: &mut S,
        block_context: &BlockContext,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let mut tx_exec_info = self.validate(state, block_context)?;

        let (fee_transfer_info, actual_fee) =
            self.charge_fee(state, &tx_exec_info.actual_resources, block_context)?;

        state.set_contract_class(&self.class_hash, &self.contract_class)?;

        tx_exec_info.set_fee_info(actual_fee, fee_transfer_info);

        Ok(tx_exec_info)
    }

    pub(crate) fn create_for_simulation(
        &self,
        skip_validate: bool,
        skip_execute: bool,
        skip_fee_transfer: bool,
    ) -> Transaction {
        let tx = Declare {
            skip_validate,
            skip_execute,
            skip_fee_transfer,
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
    use cairo_vm::{
        felt::{felt_str, Felt252},
        vm::runners::cairo_runner::ExecutionResources,
    };
    use lazy_static::lazy_static;
    use num_traits::{One, Zero};
    use std::{collections::HashMap, path::PathBuf};

    use super::Declare;

    lazy_static! {
        /// The address of the account used for testing.
        static ref ACCOUNT_ADDRESS: Address = Address(1234.into());
        static ref VALIDATE_ENTRYPOINT_SELECTOR: Option<Felt252> = Some(VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone());
        static ref ACCOUNT_CONTRACT_CLASS: ContractClass = ContractClass::from_path("starknet_programs/account_without_validation.json").unwrap();
        static ref ACCOUNT_CLASS_HASH_FELT: Felt252 = compute_deprecated_class_hash(&ACCOUNT_CONTRACT_CLASS).unwrap();
        static ref ACCOUNT_CLASS_HASH: [u8; 32] = felt_to_hash(&ACCOUNT_CLASS_HASH_FELT);
    }

    fn setup_state() -> CachedState<InMemoryStateReader> {
        // Since in this test we want to test that we can declare a contract.
        // We can assume that we have an existing account contract in the state.
        // So we just insert it manually in the state.
        let contract_class =
            ContractClass::from_path("starknet_programs/account_without_validation.json").unwrap();
        let mut contract_class_cache = HashMap::new();
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = hash.to_be_bytes();
        contract_class_cache.insert(class_hash, contract_class.clone());

        // store sender_address into the state reader.
        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(ACCOUNT_ADDRESS.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(ACCOUNT_ADDRESS.clone(), Felt252::new(1));

        CachedState::new(state_reader, Some(contract_class_cache), None)
    }

    #[test]
    fn declare_validate_fibonacci() {
        // setup a state with an already deployed account.
        let mut state = setup_state();

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        // create a Declare transaction to declare the fibonacci contract.
        let declare = Declare::new(
            fib_contract_class,
            StarknetChainId::TestNet.to_felt(),
            ACCOUNT_ADDRESS.clone(),
            0,
            1.into(),
            Vec::new(),
            Felt252::one(), // must be one to match the account's nonce
            None,
        )
        .unwrap();

        // Calldata is the class hash represented as a Felt252
        let calldata = [felt_str!(
            "151449101692423517761547521693863750221386499114738230243355039033913267347"
        )]
        .to_vec();

        let expected_validate_info = Some(CallInfo {
            caller_address: Address(0.into()),
            call_type: Some(CallType::Call),
            contract_address: ACCOUNT_ADDRESS.clone(),
            entry_point_selector: VALIDATE_ENTRYPOINT_SELECTOR.clone(),
            entry_point_type: Some(EntryPointType::External),
            calldata,
            class_hash: Some(ACCOUNT_CLASS_HASH.clone()),
            execution_resources: ExecutionResources {
                n_steps: 12,
                ..Default::default()
            },
            ..Default::default()
        });

        let actual_resources = HashMap::from([
            ("l1_gas_usage".to_string(), 0),
            ("range_check_builtin".to_string(), 57),
            ("pedersen_builtin".to_string(), 15),
        ]);

        let transaction_exec_info = TransactionExecutionInfo::new(
            expected_validate_info,
            None,
            None,
            0,
            actual_resources,
            Some(TransactionType::Declare),
        );

        assert_eq!(
            declare
                .validate(&mut state, &BlockContext::default())
                .unwrap(),
            transaction_exec_info
        );
    }

    #[test]
    fn verify_version_zero_should_fail_max_fee() {
        let mut state = setup_state();

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        let max_fee = 1000;
        let version = 0.into();

        // Declare tx should fail because max_fee > 0 and version == 0
        let declare = Declare::new(
            fib_contract_class,
            StarknetChainId::TestNet.to_felt(),
            Address(Felt252::one()),
            max_fee,
            version,
            Vec::new(),
            Felt252::from(max_fee),
            None,
        )
        .unwrap();

        let validate_exec_info = declare.validate(&mut state, &BlockContext::default());
        assert!(validate_exec_info.is_err());
        assert_matches!(
            validate_exec_info.unwrap_err(),
            TransactionError::InvalidMaxFee
        );
    }

    #[test]
    fn verify_version_zero_should_fail_nonce() {
        let mut state = setup_state();

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        let nonce = Felt252::from(148);
        let version = 0.into();

        // Declare tx should fail because nonce > 0 and version == 0
        let declare = Declare::new(
            fib_contract_class,
            StarknetChainId::TestNet.to_felt(),
            ACCOUNT_ADDRESS.clone(),
            0,
            version,
            Vec::new(),
            nonce,
            None,
        )
        .unwrap();

        // validate the transaction
        let validate_info = declare.validate(&mut state, &Default::default());
        // check that the transaction failed.
        assert!(validate_info.is_err());
        // declare transactions with version 0 should have nonce == 0
        assert_matches!(validate_info.unwrap_err(), TransactionError::InvalidNonce);
    }

    #[test]
    fn verify_signature_should_fail_not_empty_list() {
        let mut state = setup_state();

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        let signature = vec![1.into(), 2.into()];

        // Declare tx should fail because signature is not empty
        let declare = Declare::new(
            fib_contract_class,
            StarknetChainId::TestNet.to_felt(),
            ACCOUNT_ADDRESS.clone(),
            0,
            0.into(),
            signature,
            Felt252::zero(),
            None,
        )
        .unwrap();

        let validate_info = declare.validate(&mut state, &Default::default());
        assert!(validate_info.is_err());
        assert_matches!(
            validate_info.unwrap_err(),
            TransactionError::InvalidSignature
        );
    }

    #[test]
    fn execute_class_already_declared_should_redeclare() {
        let mut state = setup_state();

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        let fib_class_hash = compute_deprecated_class_hash(&fib_contract_class).unwrap();

        // Declare same class twice
        let declare1 = Declare::new(
            fib_contract_class.clone(),
            StarknetChainId::TestNet.to_felt(),
            ACCOUNT_ADDRESS.clone(),
            0,
            1.into(),
            Vec::new(),
            1.into(),
            None,
        )
        .unwrap();

        let declare2 = Declare::new(
            fib_contract_class,
            StarknetChainId::TestNet.to_felt(),
            ACCOUNT_ADDRESS.clone(),
            0,
            1.into(),
            Vec::new(),
            2.into(),
            None,
        )
        .unwrap();

        // Execute the first declare transaction.
        let declare1_exec_info = declare1.execute(&mut state, &Default::default());

        assert!(declare1_exec_info.is_ok());
        assert!(state
            .get_contract_class(&fib_class_hash.to_be_bytes())
            .is_ok());

        // Execute the second declare transaction.
        // It should run fine and re-declare the fibonacci contract class.
        let declare2_exec_info = declare2.execute(&mut state, &Default::default());

        // check that we successfully got a contract class.
        assert!(declare2_exec_info.is_ok());
        assert!(state
            .get_contract_class(&fib_class_hash.to_be_bytes())
            .is_ok());
    }

    #[test]
    fn execute_transaction_twice_should_fail() {
        let mut state = setup_state();
        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        // Declare same class twice
        let declare = Declare::new(
            fib_contract_class,
            StarknetChainId::TestNet.to_felt(),
            ACCOUNT_ADDRESS.clone(),
            0,
            1.into(),
            Vec::new(),
            1.into(),
            None,
        )
        .unwrap();

        // execute the transaction for the first time...
        let first_exec_info = declare.execute(&mut state, &BlockContext::default());
        // it should succeed.
        assert!(first_exec_info.is_ok());
        // execute the same transaction again...
        let second_exec_info = declare.execute(&mut state, &BlockContext::default());
        // it should fail
        assert!(second_exec_info.is_err());
        assert_matches!(
            second_exec_info.unwrap_err(),
            TransactionError::InvalidTransactionNonce { .. }
        )
    }

    #[test]
    fn validate_transaction_should_fail() {
        // Instantiate CachedState
        let contract_class_cache = HashMap::new();

        let state_reader = InMemoryStateReader::default();

        let mut state = CachedState::new(state_reader, Some(contract_class_cache), None);

        // There are no account contracts in the state, so the transaction should fail
        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        let declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            1.into(),
            Vec::new(),
            Felt252::zero(),
            None,
        )
        .unwrap();

        let declare = declare.execute(&mut state, &BlockContext::default());

        assert!(declare.is_err());
        assert_matches!(
            declare.unwrap_err(),
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

        let mut state = CachedState::new(state_reader, Some(contract_class_cache), None);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_contract_class =
            ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // Use non-zero value so that the actual fee calculation is done
        let declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            10,
            1.into(),
            Vec::new(),
            Felt252::zero(),
            None,
        )
        .unwrap();

        // We expect a fee transfer failure because the fee token contract is not set up
        assert_matches!(
            declare.execute(&mut state, &BlockContext::default()),
            Err(TransactionError::FeeTransferError(_))
        );
    }
}
