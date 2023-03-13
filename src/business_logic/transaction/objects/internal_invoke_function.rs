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
use felt::Felt;
use num_traits::{ToPrimitive, Zero};

pub(crate) struct InternalInvokeFunction {
    pub(crate) contract_address: Address,
    entry_point_selector: Felt,
    #[allow(dead_code)]
    entry_point_type: EntryPointType,
    calldata: Vec<Felt>,
    tx_type: TransactionType,
    version: u64,
    validate_entry_point_selector: Felt,
    hash_value: Felt,
    signature: Vec<Felt>,
    max_fee: u64,
    nonce: Option<Felt>,
}

impl InternalInvokeFunction {
    #![allow(unused)] // TODO: delete once used
    pub fn new(
        contract_address: Address,
        entry_point_selector: Felt,
        max_fee: u64,
        calldata: Vec<Felt>,
        signature: Vec<Felt>,
        chain_id: Felt,
        nonce: Option<Felt>,
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
            contract_address.clone(),
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
        T: Default + State + StateReader,
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
        T: Default + State + StateReader,
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
        T: Default + State + StateReader + Clone,
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
        S: Clone + Default + State + StateReader,
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

    /// Calculates actual fee used by the transaction using the execution
    /// info returned by apply(), then updates the transaction execution info with the data of the fee.  
    pub fn execute<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let concurrent_exec_info = self.apply(state, general_config)?;
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
    entry_point_selector: Felt,
    nonce: Option<Felt>,
    version: u64,
) -> Result<(Felt, Vec<u64>), TransactionError> {
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
                let val = n
                    .to_u64()
                    .ok_or(TransactionError::InvalidFeltConversionU64)?;
                let additional_data = [val].to_vec();
                let entry_point_selector_field = Felt::zero();
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
            fact_state::{
                contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
            },
            state::cached_state::CachedState,
        },
        services::api::contract_class::ContractClass,
    };
    use num_traits::Num;
    use std::{collections::HashMap, path::PathBuf};

    #[test]
    fn test_apply_specific_concurrent_changes() {
        let internal_invoke_function = InternalInvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt::from_str_radix(
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
        let state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
        let mut state = CachedState::new(state_reader, None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        // Set contract_class
        let class_hash: [u8; 32] = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/fibonacci.json")).unwrap();
        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        // Set contact_state
        let contract_state = ContractState::new([1; 32], Felt::new(0), HashMap::new());
        state.state_reader.contract_states.insert(
            internal_invoke_function.contract_address.clone(),
            contract_state,
        );

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
        assert_eq!(result.call_info.unwrap().retdata, vec![Felt::new(144)]);
    }
}
