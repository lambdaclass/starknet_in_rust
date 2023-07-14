use super::{verify_version, Transaction};
use crate::core::contract_address::{compute_casm_class_hash, compute_sierra_class_hash};
use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;

use crate::{
    core::transaction_hash::calculate_declare_v2_transaction_hash,
    definitions::{
        block_context::BlockContext,
        constants::{INITIAL_GAS_COST, VALIDATE_DECLARE_ENTRY_POINT_SELECTOR},
        transaction_type::TransactionType,
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType,
        TransactionExecutionContext, TransactionExecutionInfo,
    },
    state::state_api::{State, StateReader},
    state::ExecutionResourcesManager,
    transaction::{
        error::TransactionError,
        fee::{calculate_tx_fee, execute_fee_transfer, FeeInfo},
        invoke_function::verify_no_calls_to_other_contracts,
    },
    utils::{calculate_tx_resources, Address},
};
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
use cairo_vm::felt::Felt252;
use num_traits::Zero;
use std::collections::HashMap;

/// Represents a declare transaction in the starknet network.
/// Declare creates a blueprint of a contract class that is used to deploy instances of the contract
/// DeclareV2 is meant to be used with the new cairo contract sintax, starting from Cairo1.
#[derive(Debug, Clone)]
pub struct DeclareV2 {
    pub sender_address: Address,
    pub tx_type: TransactionType,
    pub validate_entry_point_selector: Felt252,
    pub version: Felt252,
    pub max_fee: u128,
    pub signature: Vec<Felt252>,
    pub nonce: Felt252,
    pub compiled_class_hash: Felt252,
    pub sierra_contract_class: SierraContractClass,
    pub sierra_class_hash: Felt252,
    pub hash_value: Felt252,
    pub casm_class: Option<CasmContractClass>,
    pub skip_validate: bool,
    pub skip_execute: bool,
    pub skip_fee_transfer: bool,
}

impl DeclareV2 {
    /// Creates a new instance of a [DeclareV2].
    /// It will calculate the sierra class hash and the transaction hash.
    /// ## Parameters:
    /// - sierra_contract_class: The sierra contract class of the contract to declare
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

    /// Creates a new instance of a declare with a precomputed sierra class hash and transaction hash.
    /// ## Parameters:
    /// - sierra_contract_class: The sierra contract class of the contract to declare
    /// - sierra_class_hash: The precomputed hash for the sierra contract
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
        sierra_contract_class: &SierraContractClass,
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
        let validate_entry_point_selector = VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone();

        let internal_declare = DeclareV2 {
            sierra_contract_class: sierra_contract_class.to_owned(),
            sierra_class_hash,
            sender_address,
            tx_type: TransactionType::Declare,
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
        };

        verify_version(
            &internal_declare.version,
            internal_declare.max_fee,
            &internal_declare.nonce,
            &internal_declare.signature,
        )?;

        Ok(internal_declare)
    }

    // creates a new instance of a declare but without the computation of the transaction hash.
    /// ## Parameters:
    /// - sierra_contract_class: The sierra contract class of the contract to declare
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

    /// Creates a new instance of a [DeclareV2] but without the computation of the sierra class hash.
    /// ## Parameters:
    /// - sierra_contract_class: The sierra contract class of the contract to declare
    /// - sierra_class_hash: The precomputed hash for the sierra contract
    /// - compiled_class_hash: the class hash of the contract compiled with Cairo1 or newer.
    /// - chain_id: Id of the network where is going to be declare, those can be: Mainnet, Testnet.
    /// - sender_address: The address of the account declaring the contract.
    /// - max_fee: refers to max amount of fee that a declare takes.
    /// - version: The version of cairo contract being declare.
    /// - signature: Array of felts with the signatures of the contract.
    /// - nonce: The nonce of the contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_sierra_class_hash(
        sierra_contract_class: &SierraContractClass,
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

    /// Calculates and charges the actual fee.
    /// ## Parameter:
    /// - state: An state that implements the State and StateReader traits.
    /// - resources: the resources that are in use by the contract
    /// - block_context: The block that contains the execution context
    pub fn charge_fee<S: State + StateReader>(
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

    // TODO: delete once used
    #[allow(dead_code)]
    fn handle_nonce<S: State + StateReader>(&self, state: &mut S) -> Result<(), TransactionError> {
        if self.version.is_zero() {
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

    /// Execute the validation of the contract in the cairo-vm. Returns a TransactionExecutionInfo if succesful.
    /// ## Parameter:
    /// - state: An state that implements the State and StateReader traits.
    /// - block_context: The block that contains the execution context
    pub fn execute<S: State + StateReader>(
        &self,
        state: &mut S,
        block_context: &BlockContext,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        verify_version(&self.version, self.max_fee, &self.nonce, &self.signature)?;

        let initial_gas = INITIAL_GAS_COST;

        let mut resources_manager = ExecutionResourcesManager::default();

        let (validate_info, _remaining_gas) = if self.skip_validate {
            (None, 0)
        } else {
            let (info, gas) = self.run_validate_entrypoint(
                initial_gas,
                state,
                &mut resources_manager,
                block_context,
            )?;
            (Some(info), gas)
        };

        let storage_changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[validate_info.clone()],
            self.tx_type,
            storage_changes,
            None,
        )?;

        let (fee_transfer_info, actual_fee) =
            self.charge_fee(state, &actual_resources, block_context)?;
        self.compile_and_store_casm_class(state)?;

        let mut tx_exec_info = TransactionExecutionInfo::new_without_fee_info(
            validate_info,
            None,
            actual_resources,
            Some(self.tx_type),
        );
        tx_exec_info.set_fee_info(actual_fee, fee_transfer_info);

        Ok(tx_exec_info)
    }

    pub(crate) fn compile_and_store_casm_class<S: State + StateReader>(
        &self,
        state: &mut S,
    ) -> Result<(), TransactionError> {
        let casm_class = match &self.casm_class {
            None => {
                CasmContractClass::from_contract_class(self.sierra_contract_class.clone(), true)
                    .map_err(|e| TransactionError::SierraCompileError(e.to_string()))?
            }
            Some(casm_contract_class) => casm_contract_class.clone(),
        };

        let casm_class_hash = compute_casm_class_hash(&casm_class)?;
        if casm_class_hash != self.compiled_class_hash {
            return Err(TransactionError::InvalidCompiledClassHash(
                casm_class_hash.to_string(),
                self.compiled_class_hash.to_string(),
            ));
        }
        state.set_compiled_class_hash(&self.sierra_class_hash, &self.compiled_class_hash)?;
        state.set_compiled_class(&self.compiled_class_hash, casm_class)?;

        Ok(())
    }

    fn run_validate_entrypoint<S: State + StateReader>(
        &self,
        mut remaining_gas: u128,
        state: &mut S,
        resources_manager: &mut ExecutionResourcesManager,
        block_context: &BlockContext,
    ) -> Result<(CallInfo, u128), TransactionError> {
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

        let call_info = if self.skip_execute {
            None
        } else {
            Some(entry_point.execute(
                state,
                block_context,
                resources_manager,
                &mut tx_execution_context,
                false,
            )?)
        };
        let call_info = verify_no_calls_to_other_contracts(&call_info)?;
        remaining_gas -= call_info.gas_consumed;

        Ok((call_info, remaining_gas))
    }

    // ---------------
    //   Simulation
    // ---------------
    pub(crate) fn create_for_simulation(
        &self,
        skip_validate: bool,
        skip_execute: bool,
        skip_fee_transfer: bool,
    ) -> Transaction {
        let tx = DeclareV2 {
            skip_validate,
            skip_execute,
            skip_fee_transfer,
            ..self.clone()
        };

        Transaction::DeclareV2(Box::new(tx))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs::File, io::BufReader, path::PathBuf};

    use super::DeclareV2;
    use crate::core::contract_address::compute_casm_class_hash;
    use crate::services::api::contract_classes::compiled_class::CompiledClass;
    use crate::state::state_api::StateReader;
    use crate::{
        state::cached_state::CachedState, state::in_memory_state_reader::InMemoryStateReader,
        utils::Address,
    };
    use cairo_lang_starknet::casm_contract_class::CasmContractClass;
    use cairo_vm::felt::Felt252;
    use num_traits::{One, Zero};

    #[test]
    fn create_declare_v2_test() {
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
        let casm_contract_class_cache = HashMap::new();
        let state_reader = InMemoryStateReader::default();
        let mut state = CachedState::new(state_reader, None, Some(casm_contract_class_cache));

        // call compile and store
        assert!(internal_declare
            .compile_and_store_casm_class(&mut state)
            .is_ok());

        // test we  can retreive the data
        let expected_casm_class = CasmContractClass::from_contract_class(
            internal_declare.sierra_contract_class.clone(),
            true,
        )
        .unwrap();

        let casm_class = match state
            .get_contract_class(&internal_declare.compiled_class_hash.to_be_bytes())
            .unwrap()
        {
            CompiledClass::Casm(casm) => *casm,
            _ => unreachable!(),
        };

        assert_eq!(expected_casm_class, casm_class);
    }
}
