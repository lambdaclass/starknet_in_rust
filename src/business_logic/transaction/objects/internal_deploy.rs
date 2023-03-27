use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, TransactionExecutionContext, TransactionExecutionInfo},
        },
        fact_state::state::ExecutionResourcesManager,
        state::state_api::{State, StateReader},
        transaction::error::TransactionError,
    },
    core::{
        contract_address::starknet_contract_address::compute_class_hash,
        errors::syscall_handler_errors::SyscallHandlerError,
        transaction_hash::starknet_transaction_hash::calculate_deploy_transaction_hash,
    },
    definitions::{
        constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR, general_config::StarknetGeneralConfig,
        transaction_type::TransactionType,
    },
    hash_utils::calculate_contract_address,
    services::api::contract_class::{ContractClass, EntryPointType},
    starkware_utils::starkware_errors::StarkwareError,
    utils::{calculate_tx_resources, felt_to_hash, Address, ClassHash},
};
use felt::Felt252;
use num_traits::Zero;

pub struct InternalDeploy {
    pub(crate) hash_value: Felt252,
    pub(crate) version: u64,
    pub(crate) contract_address: Address,
    pub(crate) _contract_address_salt: Address,
    pub(crate) contract_hash: ClassHash,
    pub(crate) constructor_calldata: Vec<Felt252>,
    pub(crate) tx_type: TransactionType,
}

impl InternalDeploy {
    pub fn new(
        contract_address_salt: Address,
        contract_class: ContractClass,
        constructor_calldata: Vec<Felt252>,
        chain_id: Felt252,
        version: u64,
    ) -> Result<Self, SyscallHandlerError> {
        let class_hash = compute_class_hash(&contract_class)
            .map_err(|_| SyscallHandlerError::ErrorComputingHash)?;

        let contract_hash: ClassHash = felt_to_hash(&class_hash);
        let contract_address = Address(calculate_contract_address(
            &contract_address_salt,
            &class_hash,
            &constructor_calldata,
            Address(Felt252::zero()),
        )?);

        let hash_value = calculate_deploy_transaction_hash(
            version,
            &contract_address,
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

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn class_hash(&self) -> ClassHash {
        self.contract_hash
    }

    pub fn apply<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        state.deploy_contract(self.contract_address.clone(), self.contract_hash)?;
        let class_hash: ClassHash = self.contract_hash;
        let contract_class = state.get_contract_class(&class_hash)?;

        let constructors = contract_class
            .entry_points_by_type()
            .get(&EntryPointType::Constructor);

        if constructors.map(Vec::is_empty).unwrap_or(true) {
            // Contract has no constructors
            Ok(self.handle_empty_constructor(state)?)
        } else {
            self.invoke_constructor(state, general_config)
        }
    }

    pub fn handle_empty_constructor<T: Default + State + StateReader + Clone>(
        &self,
        state: &mut T,
    ) -> Result<TransactionExecutionInfo, StarkwareError> {
        if !self.constructor_calldata.is_empty() {
            return Err(StarkwareError::TransactionFailed);
        }

        let class_hash: ClassHash = self.contract_hash;
        let call_info = CallInfo::empty_constructor_call(
            self.contract_address.clone(),
            Address(Felt252::zero()),
            Some(class_hash),
        );

        let resources_manager = ExecutionResourcesManager::default();

        let changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(call_info.clone())],
            self.tx_type,
            changes,
            None,
        )
        .map_err(|_| StarkwareError::UnexpectedHolesL2toL1Messages)?;

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                None,
                Some(call_info),
                actual_resources,
                Some(self.tx_type),
            ),
        )
    }

    pub fn invoke_constructor<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.constructor_calldata.clone(),
            CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone(),
            Address(Felt252::zero()),
            EntryPointType::Constructor,
            None,
            None,
        );

        let tx_execution_context = TransactionExecutionContext::new(
            Address(Felt252::zero()),
            self.hash_value.clone(),
            Vec::new(),
            0,
            Felt252::zero(),
            general_config.invoke_tx_max_n_steps,
            self.version,
        );

        let mut resources_manager = ExecutionResourcesManager::default();
        let call_info = call.execute(
            state,
            general_config,
            &mut resources_manager,
            &tx_execution_context,
        )?;

        let changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(call_info.clone())],
            self.tx_type,
            changes,
            None,
        )?;

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                None,
                Some(call_info),
                actual_resources,
                Some(self.tx_type),
            ),
        )
    }

    /// Calculates actual fee used by the transaction using the execution
    /// info returned by apply(), then updates the transaction execution info with the data of the fee.
    pub fn execute<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let concurrent_exec_info = self.apply(state, general_config)?;
        let (fee_transfer_info, actual_fee) = (None, 0);

        Ok(
            TransactionExecutionInfo::from_concurrent_state_execution_info(
                concurrent_exec_info,
                actual_fee,
                fee_transfer_info,
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        business_logic::{
            fact_state::in_memory_state_reader::InMemoryStateReader,
            state::cached_state::CachedState,
        },
        utils::calculate_sn_keccak,
    };

    #[test]
    fn invoke_constructor_test() {
        // Instantiate CachedState
        let state_reader = InMemoryStateReader::default();
        let mut state = CachedState::new(state_reader, Some(Default::default()));

        // Set contract_class
        let class_hash: ClassHash = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/constructor.json")).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        let internal_deploy = InternalDeploy {
            hash_value: 0.into(),
            version: 0,
            contract_address: Address(1.into()),
            _contract_address_salt: Address(0.into()),
            contract_hash: class_hash,
            constructor_calldata: vec![10.into()],
            tx_type: TransactionType::Deploy,
        };

        let config = Default::default();

        let _result = internal_deploy.apply(&mut state, &config).unwrap();

        assert_eq!(
            state.get_class_hash_at(&Address(1.into())).unwrap(),
            &class_hash
        );

        let storage_key = calculate_sn_keccak("owner".as_bytes());

        assert_eq!(
            state
                .get_storage_at(&(Address(1.into()), storage_key))
                .unwrap(),
            &Felt252::from(10)
        );
    }
}
