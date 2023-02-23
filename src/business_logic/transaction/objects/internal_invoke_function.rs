use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            execution_errors::ExecutionError,
            objects::{CallInfo, TransactionExecutionContext, TransactionExecutionInfo},
        },
        fact_state::state::ExecutionResourcesManager,
        state::state_api::{State, StateReader},
        transaction::transaction_errors::TransactionError,
    },
    definitions::{
        constants::EXECUTE_ENTRY_POINT_SELECTOR, general_config::StarknetGeneralConfig,
        transaction_type::TransactionType,
    },
    services::api::contract_class::EntryPointType,
    utils::{calculate_tx_resources, Address},
};
use felt::Felt;

#[allow(dead_code)]
pub(crate) struct InternalInvokeFunction {
    contract_address: Address,
    entry_point_selector: Felt,
    _entry_point_type: EntryPointType,
    calldata: Vec<Felt>,
    _tx_type: TransactionType,
    version: u64,
    validate_entry_point_selector: Felt,
    hash_value: Felt,
    signature: Vec<Felt>,
    max_fee: u64,
    nonce: Felt,
}

impl InternalInvokeFunction {
    #[allow(dead_code)]
    fn get_execution_context(&self, n_steps: u64) -> TransactionExecutionContext {
        TransactionExecutionContext::new(
            self.contract_address.clone(),
            self.hash_value.clone(),
            self.signature.clone(),
            self.max_fee,
            self.nonce.clone(),
            n_steps,
            self.version,
        )
    }

    #[allow(dead_code)]
    fn run_validate_entrypoint<T>(
        &self,
        state: &mut T,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: &StarknetGeneralConfig,
    ) -> Result<Option<CallInfo>, ExecutionError>
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
            &self.get_execution_context(general_config.validate_max_n_steps),
        )?;

        verify_no_calls_to_other_contracts(&call_info)?;

        Ok(Some(call_info))
    }

    /// Builds the transaction execution context and executes the entry point.
    /// Returns the CallInfo.
    #[allow(dead_code)]
    fn run_execute_entrypoint<T>(
        &self,
        state: &mut T,
        general_config: &StarknetGeneralConfig,
        resources_manager: &mut ExecutionResourcesManager,
    ) -> Result<CallInfo, ExecutionError>
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
            &self.get_execution_context(general_config.invoke_tx_max_n_steps),
        )
    }

    fn _apply_specific_concurrent_changes<T>(
        &self,
        state: &mut T,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, ExecutionError>
    where
        T: Default + State + StateReader,
    {
        let mut resources_manager = ExecutionResourcesManager::default();
        let validate_info =
            self.run_validate_entrypoint(state, &mut resources_manager, general_config)?;

        // Execute transaction
        let call_info =
            self.run_execute_entrypoint(state, general_config, &mut resources_manager)?;

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &vec![Some(call_info.clone()), validate_info.clone()],
            self._tx_type.clone(),
            state.count_actual_storage_changes(),
            None,
        )?;
        let transaction_execution_info =
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                validate_info,
                Some(call_info),
                actual_resources,
                Some(self._tx_type.clone()),
            );
        Ok(transaction_execution_info)
    }
}

pub fn verify_no_calls_to_other_contracts(call_info: &CallInfo) -> Result<(), TransactionError> {
    let invoked_contract_address = call_info.contract_address.clone();
    for internal_call in call_info.gen_call_topology() {
        if internal_call.contract_address != invoked_contract_address {
            return Err(TransactionError::UnauthorizedActionOnValidate);
        }
    }
    Ok(())
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
        starknet_storage::{dict_storage::DictStorage, storage::Storage},
        utils::felt_to_hash,
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
            _entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            _tx_type: TransactionType::InvokeFunction,
            version: 0,
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: 0.into(),
        };

        // Instantiate CachedState
        let state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
        let mut state = CachedState::new(state_reader, None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        // Set contract_class
        let class_hash: [u8; 32] = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("tests/fibonacci.json")).unwrap();
        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        // Set contact_state
        let contract_state = ContractState::new([1; 32], Felt::new(0), HashMap::new());
        state
            .state_reader
            .storage
            .set_contract_state(
                &felt_to_hash(&internal_invoke_function.contract_address.0),
                &contract_state,
            )
            .unwrap();

        let result = internal_invoke_function
            ._apply_specific_concurrent_changes(&mut state, &StarknetGeneralConfig::default())
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
