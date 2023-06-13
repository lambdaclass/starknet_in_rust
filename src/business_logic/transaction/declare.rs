use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint, CallInfo, TransactionExecutionContext,
            TransactionExecutionInfo,
        },
        state::state_api::{State, StateReader},
        state::ExecutionResourcesManager,
        transaction::{
            error::TransactionError,
            fee::{calculate_tx_fee, execute_fee_transfer, FeeInfo},
        },
    },
    core::{
        contract_address::compute_deprecated_class_hash, errors::state_errors::StateError,
        transaction_hash::calculate_declare_transaction_hash,
    },
    definitions::{
        constants::VALIDATE_DECLARE_ENTRY_POINT_SELECTOR, general_config::BlockContext,
        transaction_type::TransactionType,
    },
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    utils::{
        calculate_tx_resources, felt_to_hash, verify_no_calls_to_other_contracts, Address,
        ClassHash,
    },
};
use cairo_vm::felt::Felt252;
use num_traits::Zero;
use starknet_contract_class::EntryPointType;
use std::collections::HashMap;

const VERSION_0: u64 = 0;

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
///  Represents an internal transaction in the StarkNet network that is a declaration of a Cairo
///  contract class.
#[derive(Debug)]
pub struct Declare {
    pub class_hash: ClassHash,
    pub sender_address: Address,
    pub tx_type: TransactionType,
    pub validate_entry_point_selector: Felt252,
    pub version: u64,
    pub max_fee: u128,
    pub signature: Vec<Felt252>,
    pub nonce: Felt252,
    pub hash_value: Felt252,
    pub contract_class: ContractClass,
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
        version: u64,
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
                version,
                nonce.clone(),
            )?,
        };

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
        };

        internal_declare.verify_version()?;

        Ok(internal_declare)
    }

    pub fn get_calldata(&self) -> Vec<Felt252> {
        let bytes = Felt252::from_bytes_be(&self.class_hash);
        Vec::from([bytes])
    }

    pub fn verify_version(&self) -> Result<(), TransactionError> {
        if self.version.is_zero() {
            if !self.max_fee.is_zero() {
                return Err(TransactionError::InvalidMaxFee);
            }

            if !self.nonce.is_zero() {
                return Err(TransactionError::InvalidNonce);
            }
        }

        if self.version == VERSION_0 && !self.signature.len().is_zero() {
            return Err(TransactionError::InvalidSignature);
        }
        Ok(())
    }

    /// Executes a call to the cairo-vm using the accounts_validation.cairo contract to validate
    /// the contract that is being declared. Then it returns the transaction execution info of the run.
    pub fn apply<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &BlockContext,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        self.verify_version()?;

        // validate transaction
        let mut resources_manager = ExecutionResourcesManager::default();
        let validate_info =
            self.run_validate_entrypoint(state, &mut resources_manager, tx_context)?;

        let changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &vec![validate_info.clone()],
            TransactionType::Declare,
            changes,
            None,
        )
        .map_err(|_| TransactionError::ResourcesCalculation)?;

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                validate_info,
                None,
                actual_resources,
                Some(self.tx_type),
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

    pub fn run_validate_entrypoint<S: State + StateReader>(
        &self,
        state: &mut S,
        resources_manager: &mut ExecutionResourcesManager,
        tx_context: &BlockContext,
    ) -> Result<Option<CallInfo>, TransactionError> {
        if self.version == 0 {
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

        let call_info = entry_point.execute(
            state,
            tx_context,
            resources_manager,
            &self.get_execution_context(tx_context.invoke_tx_max_n_steps),
            false,
        )?;

        verify_no_calls_to_other_contracts(&call_info)
            .map_err(|_| TransactionError::UnauthorizedActionOnValidate)?;

        Ok(Some(call_info))
    }

    /// Calculates and charges the actual fee.
    pub fn charge_fee<S: State + StateReader>(
        &self,
        state: &mut S,
        resources: &HashMap<String, usize>,
        tx_context: &BlockContext,
    ) -> Result<FeeInfo, TransactionError> {
        if self.max_fee.is_zero() {
            return Ok((None, 0));
        }

        let actual_fee = calculate_tx_fee(
            resources,
            tx_context.starknet_os_config.gas_price,
            tx_context,
        )?;

        let tx_execution_context = self.get_execution_context(tx_context.invoke_tx_max_n_steps);
        let fee_transfer_info =
            execute_fee_transfer(state, tx_context, &tx_execution_context, actual_fee)?;

        Ok((Some(fee_transfer_info), actual_fee))
    }

    fn handle_nonce<S: State + StateReader>(&self, state: &mut S) -> Result<(), TransactionError> {
        if self.version == 0 {
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
    pub fn execute<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &BlockContext,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let concurrent_exec_info = self.apply(state, tx_context)?;
        self.handle_nonce(state)?;
        // Set contract class
        match state.get_contract_class(&self.class_hash) {
            Err(StateError::NoneCompiledHash(_)) => {
                // Class is undeclared; declare it.
                state.set_contract_class(&self.class_hash, &self.contract_class)?;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {
                // Class is already declared; cannot redeclare.
                return Err(TransactionError::ClassAlreadyDeclared(self.class_hash));
            }
        }

        let (fee_transfer_info, actual_fee) =
            self.charge_fee(state, &concurrent_exec_info.actual_resources, tx_context)?;

        Ok(
            TransactionExecutionInfo::from_concurrent_state_execution_info(
                concurrent_exec_info,
                actual_fee,
                fee_transfer_info,
            ),
        )
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
    use std::{collections::HashMap, path::PathBuf};

    use crate::{
        business_logic::{
            execution::CallType, state::cached_state::CachedState,
            state::in_memory_state_reader::InMemoryStateReader,
        },
        definitions::{
            constants::VALIDATE_DECLARE_ENTRY_POINT_SELECTOR,
            general_config::{StarknetChainId, BlockContext},
            transaction_type::TransactionType,
        },
        services::api::contract_classes::deprecated_contract_class::ContractClass,
        utils::{felt_to_hash, Address},
    };

    use super::Declare;

    #[test]
    fn declare_fibonacci() {
        // accounts contract class must be stored before running declaration of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::try_from(path).unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);

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

        let mut state = CachedState::new(state_reader, Some(contract_class_cache), None);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // declare tx
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            1,
            Vec::new(),
            Felt252::zero(),
            None,
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
            "3263750508471340057496742110279857589794844827005189048727502686976772849721"
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
            ("l1_gas_usage".to_string(), 0),
            ("range_check_builtin".to_string(), 57),
            ("pedersen_builtin".to_string(), 15),
        ]);
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
                .apply(&mut state, &BlockContext::default())
                .unwrap(),
            transaction_exec_info
        );
    }

    #[test]
    fn verify_version_zero_should_fail_max_fee() {
        // accounts contract class must be stored before running declaration of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::try_from(path).unwrap();

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

        let _state = CachedState::new(state_reader, Some(contract_class_cache), None);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();
        let max_fee = 1000;
        let version = 0;

        // Declare tx should fail because max_fee > 0 and version == 0
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            max_fee,
            version,
            Vec::new(),
            Felt252::from(max_fee),
            None,
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
        let contract_class = ContractClass::try_from(path).unwrap();

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

        let _state = CachedState::new(state_reader, Some(contract_class_cache), None);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();
        let nonce = Felt252::from(148);
        let version = 0;

        // Declare tx should fail because nonce > 0 and version == 0
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            version,
            Vec::new(),
            nonce,
            None,
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
        let contract_class = ContractClass::try_from(path).unwrap();

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

        let _state = CachedState::new(state_reader, Some(contract_class_cache), None);

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();
        let signature = vec![1.into(), 2.into()];

        // Declare tx should fail because signature is not empty
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            0,
            signature,
            Felt252::zero(),
            None,
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
    fn execute_class_already_declared_should_fail() {
        // accounts contract class must be stored before running declaration of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::try_from(path).unwrap();

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

        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // Declare same class twice
        let internal_declare = Declare::new(
            fib_contract_class.clone(),
            chain_id.clone(),
            Address(Felt252::one()),
            0,
            1,
            Vec::new(),
            Felt252::zero(),
            None,
        )
        .unwrap();

        let internal_declare_error = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            1,
            Vec::new(),
            Felt252::one(),
            None,
        )
        .unwrap();

        internal_declare
            .execute(&mut state, &BlockContext::default())
            .unwrap();

        let expected_error =
            internal_declare_error.execute(&mut state, &BlockContext::default());

        // ---------------------
        //      Comparison
        // ---------------------
        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::ClassAlreadyDeclared(..)
        );
    }

    #[test]
    fn execute_transaction_twice_should_fail() {
        // accounts contract class must be stored before running declaration of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::try_from(path).unwrap();

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

        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // Declare same class twice
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            1,
            Vec::new(),
            Felt252::zero(),
            None,
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

        let state_reader = InMemoryStateReader::default();

        let mut state = CachedState::new(state_reader, Some(contract_class_cache), None);

        // There are no account contracts in the state, so the transaction should fail
        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            0,
            1,
            Vec::new(),
            Felt252::zero(),
            None,
        )
        .unwrap();

        let internal_declare_error =
            internal_declare.execute(&mut state, &BlockContext::default());

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
        let contract_class = ContractClass::try_from(path).unwrap();

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

        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // Use non-zero value so that the actual fee calculation is done
        let internal_declare = Declare::new(
            fib_contract_class,
            chain_id,
            Address(Felt252::one()),
            10,
            1,
            Vec::new(),
            Felt252::zero(),
            None,
        )
        .unwrap();

        // We expect a fee transfer failure because the fee token contract is not set up
        assert_matches!(
            internal_declare.execute(&mut state, &BlockContext::default()),
            Err(TransactionError::FeeError(e)) if e == "Fee transfer failure"
        );
    }
}
