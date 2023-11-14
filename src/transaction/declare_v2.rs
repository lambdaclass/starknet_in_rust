use super::fee::{calculate_tx_fee, charge_fee};
use super::{get_tx_version, Transaction};
use crate::core::contract_address::{compute_casm_class_hash, compute_sierra_class_hash};
use crate::definitions::constants::VALIDATE_RETDATA;
use crate::execution::execution_entry_point::ExecutionResult;
use crate::execution::gas_usage::get_onchain_data_segment_length;
use crate::execution::os_usage::ESTIMATED_DECLARE_STEPS;
use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;

use crate::services::api::contract_classes::compiled_class::CompiledClass;
use crate::services::eth_definitions::eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD;
use crate::state::cached_state::CachedState;
use crate::state::contract_class_cache::ContractClassCache;
use crate::state::state_api::StateChangesCount;
use crate::{
    core::transaction_hash::calculate_declare_v2_transaction_hash,
    definitions::{
        block_context::BlockContext,
        constants::{INITIAL_GAS_COST, VALIDATE_DECLARE_ENTRY_POINT_SELECTOR},
        transaction_type::TransactionType,
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
        TransactionExecutionInfo,
    },
    state::state_api::{State, StateReader},
    state::ExecutionResourcesManager,
    transaction::{error::TransactionError, invoke_function::verify_no_calls_to_other_contracts},
    utils::{calculate_tx_resources, Address},
};
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
use cairo_vm::felt::Felt252;
use num_traits::Zero;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

/// Represents a declare transaction in the starknet network.
/// Declare creates a blueprint of a contract class that is used to deploy instances of the contract
/// DeclareV2 is meant to be used with the new cairo contract sintax, starting from Cairo1.
#[derive(Debug, Clone)]
pub struct DeclareV2 {
    pub sender_address: Address,
    pub validate_entry_point_selector: Felt252,
    pub version: Felt252,
    pub max_fee: u128,
    pub signature: Vec<Felt252>,
    pub nonce: Felt252,
    pub compiled_class_hash: Felt252,
    pub sierra_contract_class: Option<SierraContractClass>,
    pub sierra_class_hash: Felt252,
    pub hash_value: Felt252,
    pub casm_class: Option<CasmContractClass>,
    pub skip_validate: bool,
    pub skip_execute: bool,
    pub skip_fee_transfer: bool,
    pub skip_nonce_check: bool,
}

impl DeclareV2 {
    /// Creates a new instance of a [DeclareV2].
    /// It will calculate the sierra class hash and the transaction hash.
    /// ## Parameters:
    /// - sierra_contract_class: The sierra contract class of the contract to declare
    /// - casm_contract_class: The casm contract class of the contract to declare. This is optional.
    /// - compiled_class_hash: the class hash of the contract compiled with Cairo1 or newer.
    /// - chain_id: Id of the network where is going to be declare, those can be: Mainnet, Testnet.
    /// - sender_address: The address of the account declaring the contract.
    /// - max_fee: refers to max amount of fee that a declare takes.
    /// - version: The version of cairo contract being declare.
    /// - signature: Array of felts with the signatures of the contract.
    /// - nonce: The nonce of the contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sierra_contract_class: &SierraContractClass,
        casm_contract_class: Option<CasmContractClass>,
        compiled_class_hash: Felt252,
        chain_id: Felt252,
        sender_address: Address,
        max_fee: u128,
        version: Felt252,
        signature: Vec<Felt252>,
        nonce: Felt252,
    ) -> Result<Self, TransactionError> {
        let sierra_class_hash = compute_sierra_class_hash(sierra_contract_class)?;

        let hash_value = calculate_declare_v2_transaction_hash(
            sierra_class_hash.clone(),
            compiled_class_hash.clone(),
            chain_id,
            &sender_address,
            max_fee,
            version.clone(),
            nonce.clone(),
        )?;

        Self::new_with_sierra_class_hash_and_tx_hash(
            Some(sierra_contract_class.clone()),
            sierra_class_hash,
            casm_contract_class,
            compiled_class_hash,
            sender_address,
            max_fee,
            version,
            signature,
            nonce,
            hash_value,
        )
    }

    /// Creates a new instance of a declare with a precomputed sierra class hash and transaction hash.
    /// ## Parameters:
    /// - sierra_contract_class: The sierra contract class of the contract to declare
    /// - sierra_class_hash: The precomputed hash for the sierra contract
    /// - casm_contract_class: The casm contract class of the contract to declare. This is optional.
    /// - compiled_class_hash: the class hash of the contract compiled with Cairo1 or newer.
    /// - sender_address: The address of the account declaring the contract.
    /// - max_fee: refers to max amount of fee that a declare takes.
    /// - version: The version of cairo contract being declare.
    /// - signature: Array of felts with the signatures of the contract.
    /// - nonce: The nonce of the contract.
    /// - hash_value: The transaction hash_value.
    /// SAFETY: if `sierra_class_hash` doesn't correspond to the `sierra_contract_class` invariants
    /// may not hold.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_sierra_class_hash_and_tx_hash(
        sierra_contract_class: Option<SierraContractClass>,
        sierra_class_hash: Felt252,
        casm_contract_class: Option<CasmContractClass>,
        compiled_class_hash: Felt252,
        sender_address: Address,
        max_fee: u128,
        version: Felt252,
        signature: Vec<Felt252>,
        nonce: Felt252,
        hash_value: Felt252,
    ) -> Result<Self, TransactionError> {
        let version = get_tx_version(version);
        let validate_entry_point_selector = VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone();

        let internal_declare = DeclareV2 {
            sierra_contract_class: sierra_contract_class.to_owned(),
            sierra_class_hash,
            sender_address,
            validate_entry_point_selector,
            version,
            max_fee,
            signature,
            nonce,
            compiled_class_hash,
            hash_value,
            casm_class: casm_contract_class,
            skip_execute: false,
            skip_validate: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        };

        Ok(internal_declare)
    }

    // creates a new instance of a declare but without the computation of the transaction hash.
    /// ## Parameters:
    /// - sierra_contract_class: The sierra contract class of the contract to declare.
    /// - casm_contract_class: The casm contract class of the contract to declare. This is optional.
    /// - compiled_class_hash: the class hash of the contract compiled with Cairo1 or newer.
    /// - sender_address: The address of the account declaring the contract.
    /// - max_fee: refers to max amount of fee that a declare takes.
    /// - version: The version of cairo contract being declare.
    /// - signature: Array of felts with the signatures of the contract.
    /// - nonce: The nonce of the contract.
    /// - hash_value: The transaction hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_tx_hash(
        sierra_contract_class: &SierraContractClass,
        casm_contract_class: Option<CasmContractClass>,
        compiled_class_hash: Felt252,
        sender_address: Address,
        max_fee: u128,
        version: Felt252,
        signature: Vec<Felt252>,
        nonce: Felt252,
        hash_value: Felt252,
    ) -> Result<Self, TransactionError> {
        let sierra_class_hash = compute_sierra_class_hash(sierra_contract_class)?;

        Self::new_with_sierra_class_hash_and_tx_hash(
            Some(sierra_contract_class.clone()),
            sierra_class_hash,
            casm_contract_class,
            compiled_class_hash,
            sender_address,
            max_fee,
            version,
            signature,
            nonce,
            hash_value,
        )
    }

    /// Creates a new instance of a [DeclareV2] but without the computation of the sierra class hash.
    /// ## Parameters:
    /// - sierra_contract_class: The sierra contract class of the contract to declare
    /// - sierra_class_hash: The precomputed hash for the sierra contract
    /// - casm_contract_class: The casm contract class of the contract to declare. This is optional.
    /// - compiled_class_hash: the class hash of the contract compiled with Cairo1 or newer.
    /// - chain_id: Id of the network where is going to be declare, those can be: Mainnet, Testnet.
    /// - sender_address: The address of the account declaring the contract.
    /// - max_fee: refers to max amount of fee that a declare takes.
    /// - version: The version of cairo contract being declare.
    /// - signature: Array of felts with the signatures of the contract.
    /// - nonce: The nonce of the contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_sierra_class_hash(
        sierra_contract_class: Option<SierraContractClass>,
        sierra_class_hash: Felt252,
        casm_contract_class: Option<CasmContractClass>,
        compiled_class_hash: Felt252,
        chain_id: Felt252,
        sender_address: Address,
        max_fee: u128,
        version: Felt252,
        signature: Vec<Felt252>,
        nonce: Felt252,
    ) -> Result<Self, TransactionError> {
        let hash_value = calculate_declare_v2_transaction_hash(
            sierra_class_hash.clone(),
            compiled_class_hash.clone(),
            chain_id,
            &sender_address,
            max_fee,
            version.clone(),
            nonce.clone(),
        )?;

        Self::new_with_sierra_class_hash_and_tx_hash(
            sierra_contract_class,
            sierra_class_hash,
            casm_contract_class,
            compiled_class_hash,
            sender_address,
            max_fee,
            version,
            signature,
            nonce,
            hash_value,
        )
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    //  Account Functions
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    /// creates the a new TransactionExecutionContexts which represent the state of the net after executing the contract.
    /// ## Parameter:
    /// n_steps: the number of steps that are required to execute the contract.
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

    /// returns the calldata with which the contract is executed
    pub fn get_calldata(&self) -> Vec<Felt252> {
        let bytes = self.compiled_class_hash.clone();
        Vec::from([bytes])
    }

    fn handle_nonce<S: State + StateReader>(&self, state: &mut S) -> Result<(), TransactionError> {
        let contract_address = &self.sender_address;
        let current_nonce = state.get_nonce_at(contract_address)?;
        if current_nonce != self.nonce && !self.skip_nonce_check {
            return Err(TransactionError::InvalidTransactionNonce(
                current_nonce.to_string(),
                self.nonce.to_string(),
            ));
        }

        state.increment_nonce(contract_address)?;

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
            state.get_fee_token_balance(block_context, &self.sender_address)?;
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
        let n_estimated_steps = ESTIMATED_DECLARE_STEPS;
        let onchain_data_length = get_onchain_data_segment_length(&StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
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

    /// Execute the validation of the contract in the cairo-vm. Returns a TransactionExecutionInfo if succesful.
    /// ## Parameter:
    /// - state: An state that implements the State and StateReader traits.
    /// - block_context: The block that contains the execution context
    #[tracing::instrument(level = "debug", ret, err, skip(self, state, block_context), fields(
        tx_type = ?TransactionType::Declare,
        self.version = ?self.version,
        self.sierra_class_hash = ?self.sierra_class_hash,
        self.compiled_class_hash = ?self.compiled_class_hash,
        self.hash_value = ?self.hash_value,
        self.sender_address = ?self.sender_address,
        self.nonce = ?self.nonce,
    ))]
    pub fn execute<S: StateReader, C: ContractClassCache>(
        &self,
        state: &mut CachedState<S, C>,
        block_context: &BlockContext,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        if self.version != 2.into() {
            return Err(TransactionError::UnsupportedTxVersion(
                "DeclareV2".to_string(),
                self.version.clone(),
                vec![2],
            ));
        }

        if !self.skip_fee_transfer {
            self.check_fee_balance(state, block_context)?;
        }

        self.handle_nonce(state)?;
        let initial_gas = INITIAL_GAS_COST;

        let mut resources_manager = ExecutionResourcesManager::default();

        let (execution_result, _remaining_gas) = if self.skip_validate {
            (ExecutionResult::default(), 0)
        } else {
            let (info, gas) = self.run_validate_entrypoint(
                initial_gas,
                state,
                &mut resources_manager,
                block_context,
            )?;
            (info, gas)
        };
        self.compile_and_store_casm_class(state)?;

        let storage_changes = state.count_actual_state_changes(Some((
            &block_context.starknet_os_config.fee_token_address,
            &self.sender_address,
        )))?;

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[execution_result.call_info.clone()],
            TransactionType::Declare,
            storage_changes,
            None,
            execution_result.n_reverted_steps,
        )?;

        let mut tx_execution_context =
            self.get_execution_context(block_context.invoke_tx_max_n_steps);
        let (fee_transfer_info, actual_fee) = charge_fee(
            state,
            &actual_resources,
            block_context,
            self.max_fee,
            &mut tx_execution_context,
            self.skip_fee_transfer,
        )?;

        let mut tx_exec_info = TransactionExecutionInfo::new_without_fee_info(
            execution_result.call_info,
            None,
            None,
            actual_resources,
            Some(TransactionType::Declare),
        );
        tx_exec_info.set_fee_info(actual_fee, fee_transfer_info);

        Ok(tx_exec_info)
    }

    pub(crate) fn compile_and_store_casm_class<S: State + StateReader>(
        &self,
        state: &mut S,
    ) -> Result<(), TransactionError> {
        let casm_class = match &self.casm_class {
            None => CasmContractClass::from_contract_class(
                self.sierra_contract_class
                    .clone()
                    .ok_or(TransactionError::DeclareV2NoSierraOrCasm)?,
                true,
            )
            .map_err(|e| TransactionError::SierraCompileError(e.to_string()))?,
            Some(casm_contract_class) => casm_contract_class.clone(),
        };

        let casm_class_hash = compute_casm_class_hash(&casm_class)?;
        if casm_class_hash != self.compiled_class_hash {
            return Err(TransactionError::InvalidCompiledClassHash(
                casm_class_hash.to_string(),
                self.compiled_class_hash.to_string(),
            ));
        }
        if let Some(ref class) = self.sierra_contract_class {
            state.set_sierra_program(&self.sierra_class_hash, class.sierra_program.clone())?;
        }

        state.set_compiled_class_hash(&self.sierra_class_hash, &self.compiled_class_hash)?;
        state.set_contract_class(
            &self.compiled_class_hash.to_be_bytes(),
            &CompiledClass::Casm(Arc::new(casm_class)),
        )?;

        Ok(())
    }

    fn run_validate_entrypoint<S: StateReader, C: ContractClassCache>(
        &self,
        mut remaining_gas: u128,
        state: &mut CachedState<S, C>,
        resources_manager: &mut ExecutionResourcesManager,
        block_context: &BlockContext,
    ) -> Result<(ExecutionResult, u128), TransactionError> {
        let calldata = [self.compiled_class_hash.clone()].to_vec();

        let entry_point = ExecutionEntryPoint {
            contract_address: self.sender_address.clone(),
            entry_point_selector: self.validate_entry_point_selector.clone(),
            initial_gas: remaining_gas,
            entry_point_type: EntryPointType::External,
            calldata,
            caller_address: Address(Felt252::zero()),
            code_address: None,
            class_hash: None,
            call_type: CallType::Call,
        };

        let mut tx_execution_context =
            self.get_execution_context(block_context.validate_max_n_steps);

        let execution_result = if self.skip_execute {
            ExecutionResult::default()
        } else {
            entry_point.execute(
                state,
                block_context,
                resources_manager,
                &mut tx_execution_context,
                true,
                block_context.validate_max_n_steps,
            )?
        };

        // Validate the return data
        let class_hash = state.get_class_hash_at(&self.sender_address.clone())?;
        let contract_class = state
            .get_contract_class(&class_hash)
            .map_err(|_| TransactionError::MissingCompiledClass)?;
        if let CompiledClass::Sierra(_) = contract_class {
            // The account contract class is a Cairo 1.0 contract; the `validate` entry point should
            // return `VALID`.
            if !execution_result
                .call_info
                .as_ref()
                .map(|ci| ci.retdata == vec![VALIDATE_RETDATA.clone()])
                .unwrap_or_default()
            {
                return Err(TransactionError::WrongValidateRetdata);
            }
        }

        if execution_result.call_info.is_some() {
            verify_no_calls_to_other_contracts(&execution_result.call_info)?;
            remaining_gas -= execution_result.call_info.clone().unwrap().gas_consumed;
        }

        Ok((execution_result, remaining_gas))
    }

    // ---------------
    //   Simulation
    // ---------------
    pub fn create_for_simulation(
        &self,
        skip_validate: bool,
        skip_execute: bool,
        skip_fee_transfer: bool,
        ignore_max_fee: bool,
        skip_nonce_check: bool,
    ) -> Transaction {
        let tx = DeclareV2 {
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

        Transaction::DeclareV2(Box::new(tx))
    }
}

#[cfg(test)]
mod tests {
    use super::DeclareV2;
    use crate::core::contract_address::{compute_casm_class_hash, compute_sierra_class_hash};
    use crate::definitions::block_context::{BlockContext, StarknetChainId};
    use crate::definitions::constants::QUERY_VERSION_2;
    use crate::services::api::contract_classes::compiled_class::CompiledClass;
    use crate::state::state_api::StateReader;
    use crate::transaction::error::TransactionError;
    use crate::{
        state::{
            cached_state::CachedState, contract_class_cache::PermanentContractClassCache,
            in_memory_state_reader::InMemoryStateReader,
        },
        utils::Address,
    };
    use cairo_lang_starknet::casm_contract_class::CasmContractClass;
    use cairo_vm::felt::Felt252;
    use num_traits::{One, Zero};
    use std::{fs::File, io::BufReader, path::PathBuf, sync::Arc};

    #[test]
    fn create_declare_v2_without_casm_contract_class_test() {
        // read file to create sierra contract class
        let version;
        let path;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            version = Felt252::from(2);
            path = PathBuf::from("starknet_programs/cairo2/fibonacci.sierra");
        }

        #[cfg(feature = "cairo_1_tests")]
        {
            version = Felt252::from(1);
            path = PathBuf::from("starknet_programs/cairo1/fibonacci.sierra");
        }

        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
            serde_json::from_reader(reader).unwrap();
        let sender_address = Address(1.into());
        let casm_class =
            CasmContractClass::from_contract_class(sierra_contract_class.clone(), true).unwrap();
        let casm_class_hash = compute_casm_class_hash(&casm_class).unwrap();

        // create internal declare v2

        let internal_declare = DeclareV2::new_with_tx_hash(
            &sierra_contract_class,
            None,
            casm_class_hash,
            sender_address,
            0,
            version,
            [1.into()].to_vec(),
            Felt252::zero(),
            Felt252::one(),
        )
        .unwrap();

        // crate state to store casm contract class
        let casm_contract_class_cache = PermanentContractClassCache::default();
        let state_reader = Arc::new(InMemoryStateReader::default());
        let mut state = CachedState::new(state_reader, Arc::new(casm_contract_class_cache));

        // call compile and store
        assert!(internal_declare
            .compile_and_store_casm_class(&mut state)
            .is_ok());

        // test we  can retreive the data
        let expected_casm_class = CasmContractClass::from_contract_class(
            internal_declare.sierra_contract_class.unwrap().clone(),
            true,
        )
        .unwrap();

        let casm_class = match state
            .get_contract_class(&internal_declare.compiled_class_hash.to_be_bytes())
            .unwrap()
        {
            CompiledClass::Casm(casm) => casm.as_ref().clone(),
            _ => unreachable!(),
        };

        assert_eq!(expected_casm_class, casm_class);
    }

    #[test]
    fn create_declare_v2_with_casm_contract_class_test() {
        // read file to create sierra contract class
        let version;
        let path;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            version = Felt252::from(2);
            path = PathBuf::from("starknet_programs/cairo2/fibonacci.sierra");
        }

        #[cfg(feature = "cairo_1_tests")]
        {
            version = Felt252::from(1);
            path = PathBuf::from("starknet_programs/cairo1/fibonacci.sierra");
        }

        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
            serde_json::from_reader(reader).unwrap();
        let sender_address = Address(1.into());
        let casm_class =
            CasmContractClass::from_contract_class(sierra_contract_class.clone(), true).unwrap();
        let casm_class_hash = compute_casm_class_hash(&casm_class).unwrap();

        // create internal declare v2

        let internal_declare = DeclareV2::new_with_tx_hash(
            &sierra_contract_class,
            Some(casm_class),
            casm_class_hash,
            sender_address,
            0,
            version,
            [1.into()].to_vec(),
            Felt252::zero(),
            Felt252::one(),
        )
        .unwrap();

        // crate state to store casm contract class
        let casm_contract_class_cache = PermanentContractClassCache::default();
        let state_reader = Arc::new(InMemoryStateReader::default());
        let mut state = CachedState::new(state_reader, Arc::new(casm_contract_class_cache));

        // call compile and store
        assert!(internal_declare
            .compile_and_store_casm_class(&mut state)
            .is_ok());

        // test we  can retreive the data
        let expected_casm_class = CasmContractClass::from_contract_class(
            internal_declare.sierra_contract_class.unwrap(),
            true,
        )
        .unwrap();

        let casm_class = match state
            .get_contract_class(&internal_declare.compiled_class_hash.to_be_bytes())
            .unwrap()
        {
            CompiledClass::Casm(casm) => casm.as_ref().clone(),
            _ => unreachable!(),
        };

        assert_eq!(expected_casm_class, casm_class);
    }

    #[test]
    fn create_declare_v2_test_with_version_query() {
        // read file to create sierra contract class
        let version;
        let path;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            version = QUERY_VERSION_2.clone();
            path = PathBuf::from("starknet_programs/cairo2/fibonacci.sierra");
        }

        #[cfg(feature = "cairo_1_tests")]
        {
            version = QUERY_VERSION_2.clone();
            path = PathBuf::from("starknet_programs/cairo1/fibonacci.sierra");
        }

        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
            serde_json::from_reader(reader).unwrap();
        let sierra_class_hash = compute_sierra_class_hash(&sierra_contract_class).unwrap();
        let sender_address = Address(1.into());
        let casm_class =
            CasmContractClass::from_contract_class(sierra_contract_class.clone(), true).unwrap();
        let casm_class_hash = compute_casm_class_hash(&casm_class).unwrap();

        // create internal declare v2

        let internal_declare = DeclareV2::new_with_sierra_class_hash_and_tx_hash(
            Some(sierra_contract_class),
            sierra_class_hash,
            Some(casm_class),
            casm_class_hash,
            sender_address,
            0,
            version,
            vec![],
            Felt252::zero(),
            Felt252::zero(),
        )
        .unwrap();

        // crate state to store casm contract class
        let casm_contract_class_cache = PermanentContractClassCache::default();
        let state_reader = Arc::new(InMemoryStateReader::default());
        let mut state = CachedState::new(state_reader, Arc::new(casm_contract_class_cache));

        // call compile and store
        assert!(internal_declare
            .compile_and_store_casm_class(&mut state)
            .is_ok());

        // test we  can retreive the data
        let expected_casm_class = CasmContractClass::from_contract_class(
            internal_declare.sierra_contract_class.unwrap(),
            true,
        )
        .unwrap();

        let casm_class = match state
            .get_contract_class(&internal_declare.compiled_class_hash.to_be_bytes())
            .unwrap()
        {
            CompiledClass::Casm(casm) => casm.as_ref().clone(),
            _ => unreachable!(),
        };

        assert_eq!(expected_casm_class, casm_class);
    }

    #[test]
    fn create_declare_v2_with_casm_contract_class_none_test() {
        // read file to create sierra contract class
        let version;
        let path;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            version = Felt252::from(2);
            path = PathBuf::from("starknet_programs/cairo2/fibonacci.sierra");
        }

        #[cfg(feature = "cairo_1_tests")]
        {
            version = Felt252::from(1);
            path = PathBuf::from("starknet_programs/cairo1/fibonacci.sierra");
        }

        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
            serde_json::from_reader(reader).unwrap();
        let sender_address = Address(1.into());
        let casm_class =
            CasmContractClass::from_contract_class(sierra_contract_class.clone(), true).unwrap();
        let casm_class_hash = compute_casm_class_hash(&casm_class).unwrap();

        // create internal declare v2

        let internal_declare = DeclareV2::new_with_tx_hash(
            &sierra_contract_class,
            None,
            casm_class_hash,
            sender_address,
            0,
            version,
            [1.into()].to_vec(),
            Felt252::zero(),
            Felt252::one(),
        )
        .unwrap();

        // crate state to store casm contract class
        let casm_contract_class_cache = PermanentContractClassCache::default();
        let state_reader = Arc::new(InMemoryStateReader::default());
        let mut state = CachedState::new(state_reader, Arc::new(casm_contract_class_cache));

        // call compile and store
        assert!(internal_declare
            .compile_and_store_casm_class(&mut state)
            .is_ok());

        // test we  can retreive the data
        let expected_casm_class = CasmContractClass::from_contract_class(
            internal_declare.sierra_contract_class.unwrap().clone(),
            true,
        )
        .unwrap();

        let casm_class = match state
            .get_contract_class(&internal_declare.compiled_class_hash.to_be_bytes())
            .unwrap()
        {
            CompiledClass::Casm(casm) => casm.as_ref().clone(),
            _ => unreachable!(),
        };

        assert_eq!(expected_casm_class, casm_class);
    }

    #[test]
    fn create_declare_v2_wrong_casm_class_hash_test() {
        // read file to create sierra contract class
        let version;
        let path;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            version = Felt252::from(2);
            path = PathBuf::from("starknet_programs/cairo2/fibonacci.sierra");
        }

        #[cfg(feature = "cairo_1_tests")]
        {
            version = Felt252::from(1);
            path = PathBuf::from("starknet_programs/cairo1/fibonacci.sierra");
        }

        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
            serde_json::from_reader(reader).unwrap();
        let sender_address = Address(1.into());
        let casm_class =
            CasmContractClass::from_contract_class(sierra_contract_class.clone(), true).unwrap();
        let casm_class_hash = compute_casm_class_hash(&casm_class).unwrap();

        let sended_class_hash = Felt252::from(5);
        // create internal declare v2

        let internal_declare = DeclareV2::new_with_tx_hash(
            &sierra_contract_class,
            None,
            sended_class_hash.clone(),
            sender_address,
            0,
            version,
            [1.into()].to_vec(),
            Felt252::zero(),
            Felt252::one(),
        )
        .unwrap();

        // crate state to store casm contract class
        let casm_contract_class_cache = PermanentContractClassCache::default();
        let state_reader = Arc::new(InMemoryStateReader::default());
        let mut state = CachedState::new(state_reader, Arc::new(casm_contract_class_cache));

        let expected_err = format!(
            "Invalid compiled class, expected class hash: {}, but received: {}",
            casm_class_hash, sended_class_hash
        );
        assert_eq!(
            internal_declare
                .compile_and_store_casm_class(&mut state)
                .unwrap_err()
                .to_string(),
            expected_err
        );
    }

    #[test]
    fn declarev2_wrong_version() {
        let path;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            path = PathBuf::from("starknet_programs/cairo2/fibonacci.sierra");
        }

        #[cfg(feature = "cairo_1_tests")]
        {
            path = PathBuf::from("starknet_programs/cairo1/fibonacci.sierra");
        }

        let file = File::open(path).unwrap();
        let reader = BufReader::new(file);
        let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
            serde_json::from_reader(reader).unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // declare tx
        let internal_declare = DeclareV2::new(
            &sierra_contract_class,
            None,
            Felt252::one(),
            chain_id,
            Address(Felt252::one()),
            0,
            1.into(),
            Vec::new(),
            Felt252::zero(),
        )
        .unwrap();
        let result = internal_declare.execute(
            &mut CachedState::<InMemoryStateReader, PermanentContractClassCache>::default(),
            &BlockContext::default(),
        );

        assert_matches!(
        result,
        Err(TransactionError::UnsupportedTxVersion(tx, ver, supp))
        if tx == "DeclareV2" && ver == 1.into() && supp == vec![2]);
    }
}
