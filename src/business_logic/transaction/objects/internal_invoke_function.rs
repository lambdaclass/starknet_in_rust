use std::collections::HashMap;

use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, TransactionExecutionContext, TransactionExecutionInfo},
        },
        fact_state::state::ExecutionResourcesManager,
        state::state_api::{State, StateReader},
        transaction::{
            error::TransactionError,
            fee::{calculate_tx_fee, execute_fee_transfer, FeeInfo},
        },
    },
    core::transaction_hash::starknet_transaction_hash::{
        calculate_transaction_hash_common, TransactionHashPrefix,
    },
    definitions::{
        constants::{EXECUTE_ENTRY_POINT_SELECTOR, TRANSACTION_VERSION},
        general_config::StarknetGeneralConfig,
        transaction_type::TransactionType,
    },
    public::abi::VALIDATE_ENTRY_POINT_SELECTOR,
    services::api::contract_class::EntryPointType,
    utils::{calculate_tx_resources, Address},
};
use cairo_vm::felt::Felt252;
use getset::Getters;
use num_traits::Zero;

#[derive(Debug, Getters)]
pub struct InternalInvokeFunction {
    #[getset(get = "pub")]
    contract_address: Address,
    entry_point_selector: Felt252,
    #[allow(dead_code)]
    entry_point_type: EntryPointType,
    calldata: Vec<Felt252>,
    tx_type: TransactionType,
    version: u64,
    validate_entry_point_selector: Felt252,
    #[getset(get = "pub")]
    hash_value: Felt252,
    #[getset(get = "pub")]
    signature: Vec<Felt252>,
    max_fee: u64,
    nonce: Option<Felt252>,
}

impl InternalInvokeFunction {
    pub fn new(
        contract_address: Address,
        entry_point_selector: Felt252,
        max_fee: u64,
        calldata: Vec<Felt252>,
        signature: Vec<Felt252>,
        chain_id: Felt252,
        nonce: Option<Felt252>,
    ) -> Result<Self, TransactionError> {
        let version = TRANSACTION_VERSION;
        let (entry_point_selector_field, additional_data) = preprocess_invoke_function_fields(
            entry_point_selector.clone(),
            nonce.clone(),
            version,
        )?;
        let hash_value = calculate_transaction_hash_common(
            TransactionHashPrefix::Invoke,
            version,
            &contract_address,
            entry_point_selector_field,
            &calldata,
            max_fee,
            chain_id,
            &additional_data,
        )?;
        let validate_entry_point_selector = VALIDATE_ENTRY_POINT_SELECTOR.clone();

        Ok(InternalInvokeFunction {
            contract_address,
            entry_point_selector,
            entry_point_type: EntryPointType::External,
            calldata,
            tx_type: TransactionType::InvokeFunction,
            version,
            max_fee,
            signature,
            validate_entry_point_selector,
            nonce,
            hash_value,
        })
    }

    fn get_execution_context(
        &self,
        n_steps: u64,
    ) -> Result<TransactionExecutionContext, TransactionError> {
        Ok(TransactionExecutionContext::new(
            self.contract_address.clone(),
            self.hash_value.clone(),
            self.signature.clone(),
            self.max_fee,
            self.nonce.clone().ok_or(TransactionError::MissingNonce)?,
            n_steps,
            self.version,
        ))
    }

    fn run_validate_entrypoint<T>(
        &self,
        state: &mut T,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: &StarknetGeneralConfig,
    ) -> Result<Option<CallInfo>, TransactionError>
    where
        T: State + StateReader,
    {
        if self.entry_point_selector != *EXECUTE_ENTRY_POINT_SELECTOR {
            return Ok(None);
        }
        if self.version == 0 {
            return Ok(None);
        }

        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.calldata.clone(),
            self.validate_entry_point_selector.clone(),
            Address(0.into()),
            EntryPointType::External,
            None,
            None,
        );

        let call_info = call.execute(
            state,
            general_config,
            resources_manager,
            &self
                .get_execution_context(general_config.validate_max_n_steps)
                .map_err(|_| TransactionError::InvalidTxContext)?,
        )?;

        verify_no_calls_to_other_contracts(&call_info)
            .map_err(|_| TransactionError::InvalidContractCall)?;

        Ok(Some(call_info))
    }

    /// Builds the transaction execution context and executes the entry point.
    /// Returns the CallInfo.
    fn run_execute_entrypoint<T>(
        &self,
        state: &mut T,
        general_config: &StarknetGeneralConfig,
        resources_manager: &mut ExecutionResourcesManager,
    ) -> Result<CallInfo, TransactionError>
    where
        T: State + StateReader,
    {
        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.calldata.clone(),
            self.entry_point_selector.clone(),
            Address(0.into()),
            EntryPointType::External,
            None,
            None,
        );

        call.execute(
            state,
            general_config,
            resources_manager,
            &self
                .get_execution_context(general_config.invoke_tx_max_n_steps)
                .map_err(|_| TransactionError::InvalidTxContext)?,
        )
    }

    /// Execute a call to the cairo-vm using the accounts_validation.cairo contract to validate
    /// the contract that is being declared. Then it returns the transaction execution info of the run.
    pub fn apply<T>(
        &self,
        state: &mut T,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError>
    where
        T: State + StateReader,
    {
        let mut resources_manager = ExecutionResourcesManager::default();

        let validate_info =
            self.run_validate_entrypoint(state, &mut resources_manager, general_config)?;
        // Execute transaction
        let call_info =
            self.run_execute_entrypoint(state, general_config, &mut resources_manager)?;
        let changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &vec![Some(call_info.clone()), validate_info.clone()],
            self.tx_type,
            changes,
            None,
        )?;

        let transaction_execution_info =
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                validate_info,
                Some(call_info),
                actual_resources,
                Some(self.tx_type),
            );
        Ok(transaction_execution_info)
    }

    fn charge_fee<S>(
        &self,
        state: &mut S,
        resources: &HashMap<String, usize>,
        general_config: &StarknetGeneralConfig,
    ) -> Result<FeeInfo, TransactionError>
    where
        S: State + StateReader,
    {
        if self.max_fee.is_zero() {
            return Ok((None, 0));
        }

        let actual_fee = calculate_tx_fee(
            resources,
            general_config.starknet_os_config.gas_price,
            general_config,
        )?;

        let tx_context = self.get_execution_context(general_config.invoke_tx_max_n_steps)?;
        let fee_transfer_info =
            execute_fee_transfer(state, general_config, &tx_context, actual_fee)?;

        Ok((Some(fee_transfer_info), actual_fee))
    }

    /// Calculates actual fee used by the transaction using the execution info returned by apply(),
    /// then updates the transaction execution info with the data of the fee.
    pub fn execute<S: State + StateReader>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let concurrent_exec_info = self.apply(state, general_config)?;
        self.handle_nonce(state)?;

        let (fee_transfer_info, actual_fee) = self.charge_fee(
            state,
            &concurrent_exec_info.actual_resources,
            general_config,
        )?;

        Ok(
            TransactionExecutionInfo::from_concurrent_state_execution_info(
                concurrent_exec_info,
                actual_fee,
                fee_transfer_info,
            ),
        )
    }

    fn handle_nonce<S: State + StateReader>(&self, state: &mut S) -> Result<(), TransactionError> {
        if self.version == 0 {
            return Ok(());
        }

        let contract_address = self.contract_address();

        let current_nonce = state.get_nonce_at(contract_address)?;

        match &self.nonce {
            None => {
                // TODO: Remove this once we have a better way to handle the nonce.
                Ok(())
            }
            Some(nonce) => {
                if *nonce != current_nonce {
                    return Err(TransactionError::InvalidTransactionNonce(
                        current_nonce.to_string(),
                        nonce.to_string(),
                    ));
                }
                state.increment_nonce(contract_address)?;
                Ok(())
            }
        }
    }
}

// ------------------------------------
//  Invoke internal functions utils
// ------------------------------------

pub fn verify_no_calls_to_other_contracts(call_info: &CallInfo) -> Result<(), TransactionError> {
    let invoked_contract_address = call_info.contract_address.clone();
    for internal_call in call_info.gen_call_topology() {
        if internal_call.contract_address != invoked_contract_address {
            return Err(TransactionError::UnauthorizedActionOnValidate);
        }
    }
    Ok(())
}

// Performs validation on fields related to function invocation transaction.
// InvokeFunction transaction.
// Deduces and returns fields required for hash calculation of

pub(crate) fn preprocess_invoke_function_fields(
    entry_point_selector: Felt252,
    nonce: Option<Felt252>,
    version: u64,
) -> Result<(Felt252, Vec<Felt252>), TransactionError> {
    if version == 0 || version == u64::MAX {
        match nonce {
            Some(_) => Err(TransactionError::InvokeFunctionZeroHasNonce),
            None => {
                let additional_data = Vec::new();
                let entry_point_selector_field = entry_point_selector;
                Ok((entry_point_selector_field, additional_data))
            }
        }
    } else {
        match nonce {
            Some(n) => {
                let additional_data = vec![n];
                let entry_point_selector_field = Felt252::zero();
                Ok((entry_point_selector_field, additional_data))
            }
            None => Err(TransactionError::InvokeFunctionNonZeroMissingNonce),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        business_logic::{
            fact_state::in_memory_state_reader::InMemoryStateReader,
            state::cached_state::CachedState,
        },
        definitions::general_config::StarknetChainId,
        services::api::contract_class::ContractClass,
        utils::calculate_sn_keccak,
    };
    use coverage_helper::test;
    use num_traits::Num;
    use std::{collections::HashMap, path::PathBuf};

    #[test]
    fn test_apply_specific_concurrent_changes() {
        let internal_invoke_function = InternalInvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 0,
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: Some(0.into()),
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/fibonacci.json")).unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        let result = internal_invoke_function
            .apply(&mut state, &StarknetGeneralConfig::default())
            .unwrap();

        assert_eq!(result.tx_type, Some(TransactionType::InvokeFunction));
        assert_eq!(
            result.call_info.as_ref().unwrap().class_hash,
            Some(class_hash)
        );
        assert_eq!(
            result.call_info.as_ref().unwrap().entry_point_selector,
            Some(internal_invoke_function.entry_point_selector)
        );
        assert_eq!(
            result.call_info.as_ref().unwrap().calldata,
            internal_invoke_function.calldata
        );
        assert_eq!(result.call_info.unwrap().retdata, vec![Felt252::new(144)]);
    }

    #[test]
    fn test_execute_specific_concurrent_changes() {
        let internal_invoke_function = InternalInvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 0,
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: Some(0.into()),
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/fibonacci.json")).unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        let result = internal_invoke_function
            .execute(&mut state, &StarknetGeneralConfig::default())
            .unwrap();

        assert_eq!(result.tx_type, Some(TransactionType::InvokeFunction));
        assert_eq!(
            result.call_info.as_ref().unwrap().class_hash,
            Some(class_hash)
        );
        assert_eq!(
            result.call_info.as_ref().unwrap().entry_point_selector,
            Some(internal_invoke_function.entry_point_selector)
        );
        assert_eq!(
            result.call_info.as_ref().unwrap().calldata,
            internal_invoke_function.calldata
        );
        assert_eq!(result.call_info.unwrap().retdata, vec![Felt252::new(144)]);
    }

    #[test]
    fn test_apply_invoke_entrypoint_not_found_should_fail() {
        let internal_invoke_function = InternalInvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: (*EXECUTE_ENTRY_POINT_SELECTOR).clone(),
            entry_point_type: EntryPointType::External,
            calldata: Vec::new(),
            tx_type: TransactionType::InvokeFunction,
            version: 0,
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: Some(0.into()),
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/amm.json")).unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        let expected_error =
            internal_invoke_function.apply(&mut state, &StarknetGeneralConfig::default());

        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::EntryPointNotFound
        );
    }

    #[test]
    fn test_run_validate_entrypoint_nonce_is_none_should_fail() {
        let internal_invoke_function = InternalInvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: (*EXECUTE_ENTRY_POINT_SELECTOR).clone(),
            entry_point_type: EntryPointType::External,
            calldata: Vec::new(),
            tx_type: TransactionType::InvokeFunction,
            version: 1,
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: None,
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/amm.json")).unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        let expected_error =
            internal_invoke_function.apply(&mut state, &StarknetGeneralConfig::default());

        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::InvalidTxContext
        );
    }

    #[test]
    // Test fee calculation is done correctly but payment to sequencer fails due to been WIP.
    fn test_execute_invoke_fee_payment_to_sequencer_should_fail() {
        let internal_invoke_function = InternalInvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 1,
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 1000,
            nonce: Some(0.into()),
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/fibonacci.json")).unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        let mut config = StarknetGeneralConfig::default();
        config.cairo_resource_fee_weights = HashMap::from([
            (String::from("l1_gas_usage"), 0.into()),
            (String::from("pedersen_builtin"), 16.into()),
            (String::from("range_check_builtin"), 70.into()),
        ]);

        let expected_error = internal_invoke_function.execute(&mut state, &config);
        let error_msg = "Fee transfer failure".to_string();
        assert!(expected_error.is_err());
        assert_matches!(expected_error.unwrap_err(), TransactionError::FeeError(msg) if msg == error_msg);
    }

    #[test]
    fn test_execute_invoke_actual_fee_exceeded_max_fee_should_fail() {
        let internal_invoke_function = InternalInvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 1,
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 1000,
            nonce: Some(0.into()),
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/fibonacci.json")).unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        let mut config = StarknetGeneralConfig::default();
        config.cairo_resource_fee_weights = HashMap::from([
            (String::from("l1_gas_usage"), 0.into()),
            (String::from("pedersen_builtin"), 16.into()),
            (String::from("range_check_builtin"), 70.into()),
        ]);
        config.starknet_os_config.gas_price = 1;

        let expected_error = internal_invoke_function.execute(&mut state, &config);
        let error_msg = "Actual fee exceeded max fee.".to_string();
        assert!(expected_error.is_err());
        assert_matches!(expected_error.unwrap_err(), TransactionError::FeeError(actual_error_msg) if actual_error_msg == error_msg);
    }

    #[test]
    fn test_execute_invoke_twice_should_fail() {
        let internal_invoke_function = InternalInvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 1,
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: Some(0.into()),
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/fibonacci.json")).unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        internal_invoke_function
            .execute(&mut state, &StarknetGeneralConfig::default())
            .unwrap();

        let expected_error =
            internal_invoke_function.execute(&mut state, &StarknetGeneralConfig::default());

        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::InvalidTransactionNonce(..)
        )
    }

    #[test]
    fn test_execute_inovoke_nonce_missing_should_fail() {
        let internal_invoke_function = InternalInvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 1,
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: None,
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/fibonacci.json")).unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        let expected_error =
            internal_invoke_function.execute(&mut state, &StarknetGeneralConfig::default());

        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::InvalidTxContext
        )
    }

    #[test]
    fn invoke_version_zero_with_non_zero_nonce_should_fail() {
        let expected_error = preprocess_invoke_function_fields(
            Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            Some(1.into()),
            0,
        )
        .unwrap_err();
        assert_matches!(expected_error, TransactionError::InvokeFunctionZeroHasNonce)
    }

    #[test]
    // the test should try to make verify_no_calls_to_other_contracts fail
    fn verify_no_calls_to_other_contracts_should_fail() {
        let mut call_info = CallInfo::default();
        let mut internal_calls = Vec::new();
        let internal_call = CallInfo {
            contract_address: Address(1.into()),
            ..Default::default()
        };
        internal_calls.push(internal_call);
        call_info.internal_calls = internal_calls;

        let expected_error = verify_no_calls_to_other_contracts(&call_info);

        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::UnauthorizedActionOnValidate
        );
    }

    #[test]
    fn preprocess_invoke_function_fields_nonce_is_none() {
        let entry_point_selector = Felt252::from_str_radix(
            "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
            16,
        )
        .unwrap();
        let result = preprocess_invoke_function_fields(entry_point_selector.clone(), None, 0);

        let expected_additional_data: Vec<Felt252> = Vec::new();
        let expected_entry_point_selector_field = entry_point_selector;
        assert_eq!(
            result.unwrap(),
            (
                expected_entry_point_selector_field,
                expected_additional_data
            )
        )
    }

    #[test]
    fn invoke_version_one_with_no_nonce_should_fail() {
        let expected_error = preprocess_invoke_function_fields(
            Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            None,
            1,
        );
        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::InvokeFunctionNonZeroMissingNonce
        )
    }

    /// using https://testnet-2.starkscan.co/tx/0x07b04e4d07c08efb3b3371a41ee8c38103ca4f5f26bd78bab3c0023ce2acdce9
    #[test]
    fn invoke_function_hash_1() {
        use cairo_vm::felt::felt_str;
        let tx = InternalInvokeFunction::new(
            Address(felt_str!(
                "00ce88b8eaacfba3fe9bee2f97c4ffaff2aa4fdd370db5d916b32c7226f8294f",
                16
            )),
            Felt252::from_bytes_be(&calculate_sn_keccak("__execute__".as_bytes())),
            10000000000000000,
            vec![
                felt_str!("1"),
                felt_str!(
                    "5bbf6d1290ab644867b821957e9bbc9e911d9221bbb266fd783f650a455b51e",
                    16
                ),
                felt_str!(
                    "12ead94ae9d3f9d2bdb6b847cf255f1f398193a1f88884a0ae8e18f24a037b6",
                    16
                ),
                felt_str!("0"),
                felt_str!("1"),
                felt_str!("1"),
                felt_str!("5dbfd70f8dfcce2ecc3c14a71a3ca628838dd29a", 16),
            ],
            vec![
                felt_str!(
                    "308debfd71da6e71be6edad6c9aea7bfe97fc09f2c9ded096202527f66109bc",
                    16
                ),
                felt_str!(
                    "3207b1c060bb4df5ba05285dbb2bcef94ac0c8cb11410e6a41fcb297f315094",
                    16
                ),
            ],
            StarknetChainId::TestNet2.to_felt(),
            Some(felt_str!("0")),
        )
        .unwrap();
        assert_eq!(
            tx.hash_value(),
            &felt_str!(
                "7b04e4d07c08efb3b3371a41ee8c38103ca4f5f26bd78bab3c0023ce2acdce9",
                16
            )
        );
    }

    /// using https://testnet-2.starkscan.co/tx/0x044f058f30e129f3b9b700cb997b0905b3fa3f2f6bcdfdb538f2b07c1f7214cd
    #[test]
    fn invoke_function_hash_2() {
        use cairo_vm::felt::felt_str;
        let tx = InternalInvokeFunction::new(
            Address(felt_str!(
                "0227fa557f1b177525a7c3e48fa30533f2e503ebf87be04bfa28f1ddd4ab29e0",
                16
            )),
            Felt252::from_bytes_be(&calculate_sn_keccak("__execute__".as_bytes())),
            93000000000000,
            vec![
                felt_str!("1"),
                felt_str!(
                    "62a569cd978d181d4c56aad2a9dcedae3f1d52183a4ec18fa0da2a87f617b79",
                    16
                ),
                felt_str!(
                    "2ca3b920f95277dba1fffab23b28aa0fe612c2630cba5640bd569b608d96c65",
                    16
                ),
                felt_str!("0"),
                felt_str!("1"),
                felt_str!("1"),
                felt_str!(
                    "500d61ecf16158a186d660cc069f5d66fa34fead533e2cdf386a410b0d9c10c",
                    16
                ),
            ],
            vec![
                felt_str!(
                    "13699eadc4e505d54811ac6dbccc9325bd19c2c2bed4748efa43a22b0658eda",
                    16
                ),
                felt_str!(
                    "423fce4921dabd1366699fadd9f582a4aae0603d5dd39442e71e1ca9006810d",
                    16
                ),
            ],
            StarknetChainId::TestNet2.to_felt(),
            Some(felt_str!("4")),
        )
        .unwrap();
        assert_eq!(
            tx.hash_value(),
            &felt_str!(
                "044f058f30e129f3b9b700cb997b0905b3fa3f2f6bcdfdb538f2b07c1f7214cd",
                16
            )
        );
    }

    /// using https://testnet-2.starkscan.co/tx/0x06f638138f4571bea010fe294c4d48d16f5fff9c6300d9b25e769c10b8d04b27
    #[test]
    fn invoke_function_hash_3() {
        use cairo_vm::felt::felt_str;
        let tx = InternalInvokeFunction::new(
            Address(felt_str!(
                "00ce88b8eaacfba3fe9bee2f97c4ffaff2aa4fdd370db5d916b32c7226f8294f",
                16
            )),
            Felt252::from_bytes_be(&calculate_sn_keccak("__execute__".as_bytes())),
            10000000000000000,
            vec![
                felt_str!("1"),
                felt_str!(
                    "6b0546424401c405ee594755dd62c48405e3622b284551d6c248f9febf16aa5",
                    16
                ),
                felt_str!(
                    "679c22735055a10db4f275395763a3752a1e3a3043c192299ab6b574fba8d6",
                    16
                ),
                felt_str!("0"),
                felt_str!("0"),
                felt_str!("0"),
            ],
            vec![
                felt_str!(
                    "216526bd8e86c31117ffcc57a135518ebb22293eb6ed270fa6aa055dbe86c8f",
                    16
                ),
                felt_str!(
                    "50c2fae75b03d96422588a4bd9896c4293321c08d8caff1cc708793ff71951a",
                    16
                ),
            ],
            StarknetChainId::TestNet2.to_felt(),
            Some(felt_str!("4")),
        )
        .unwrap();
        assert_eq!(
            tx.hash_value(),
            &felt_str!(
                "06f638138f4571bea010fe294c4d48d16f5fff9c6300d9b25e769c10b8d04b27",
                16
            )
        );
    }
}
