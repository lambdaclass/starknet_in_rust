use super::state_objects::FeeInfo;
use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            execution_errors::ExecutionError,
            objects::{CallInfo, TransactionExecutionContext, TransactionExecutionInfo},
        },
        fact_state::state::ExecutionResourcesManager,
        state::state_api::{State, StateReader},
    },
    core::{
        contract_address::starknet_contract_address::compute_class_hash,
        errors::syscall_handler_errors::SyscallHandlerError,
        transaction_hash::starknet_transaction_hash::calculate_deploy_transaction_hash,
    },
    definitions::{general_config::StarknetGeneralConfig, transaction_type::TransactionType},
    hash_utils::calculate_contract_address,
    services::api::contract_class::{ContractClass, EntryPointType},
    starkware_utils::starkware_errors::StarkwareError,
    utils::{calculate_sn_keccak, calculate_tx_resources, Address},
    utils_errors::UtilsError,
};
use felt::Felt;
use num_traits::Zero;
use std::collections::HashMap;

pub struct InternalDeploy {
    hash_value: Felt,
    version: u64,
    contract_address: Address,
    _contract_address_salt: Address,
    contract_hash: [u8; 32],
    constructor_calldata: Vec<Felt>,
    tx_type: TransactionType,
}

impl InternalDeploy {
    pub fn new(
        contract_address_salt: Address,
        contract_class: ContractClass,
        constructor_calldata: Vec<Felt>,
        chain_id: u64,
        version: u64,
    ) -> Result<Self, SyscallHandlerError> {
        let class_hash = compute_class_hash(&contract_class)
            .map_err(|_| SyscallHandlerError::ErrorComputingHash)?;
        let contract_hash: [u8; 32] = class_hash
            .to_string()
            .as_bytes()
            .try_into()
            .map_err(|_| UtilsError::FeltToFixBytesArrayFail(class_hash.clone()))?;
        let contract_address = Address(calculate_contract_address(
            &contract_address_salt,
            &class_hash,
            &constructor_calldata[..],
            Address(0.into()),
        )?);

        let hash_value = calculate_deploy_transaction_hash(
            version,
            contract_address.clone(),
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

    pub fn class_hash(&self) -> [u8; 32] {
        self.contract_hash
    }

    pub fn _apply_specific_concurrent_changes<S: State + StateReader + Clone + Default>(
        &self,
        mut state: S,
        general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, StarkwareError> {
        state.deploy_contract(self.contract_address.clone(), self.contract_hash)?;

        let class_hash: [u8; 32] = self.contract_hash[..]
            .try_into()
            .map_err(|_| StarkwareError::IncorrectClassHashSize)?;
        let contract_class = state.get_contract_class(&class_hash)?;

        match contract_class
            .entry_points_by_type
            .get(&EntryPointType::Constructor)
        {
            Some(entry_points) if entry_points.len() > 0 => self
                .invoke_constructor(&mut state, general_config)
                .map_err(StarkwareError::InvokeConstructor),
            _ => self.handle_empty_constructor(&mut state),
        }
    }

    pub fn _apply_specific_sequential_changes(
        &self,
        _state: impl State,
        _general_config: StarknetGeneralConfig,
        _actual_resources: HashMap<String, Felt>,
    ) -> FeeInfo {
        let fee_transfer_info = None;
        let actual_fee = 0;
        (fee_transfer_info, actual_fee)
    }

    pub fn handle_empty_constructor<T: State + StateReader>(
        &self,
        state: &mut T,
    ) -> Result<TransactionExecutionInfo, StarkwareError> {
        if self.constructor_calldata.is_empty() {
            return Err(StarkwareError::TransactionFailed);
        }

        let class_hash: [u8; 32] = self.contract_hash[..]
            .try_into()
            .map_err(|_| StarkwareError::IncorrectClassHashSize)?;
        let call_info = CallInfo::empty_constructor_call(
            self.contract_address.clone(),
            Address(0.into()),
            Some(class_hash),
        );

        let resources_manager = ExecutionResourcesManager {
            ..Default::default()
        };

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(call_info.clone())],
            self.tx_type.clone(),
            state.count_actual_storage_changes(),
            None,
        )
        .map_err(|_| StarkwareError::UnexpectedHolesL2toL1Messages)?;

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                None,
                Some(call_info),
                actual_resources,
                Some(self.tx_type.clone()),
            ),
        )
    }

    pub fn invoke_constructor<S: State + StateReader + Clone + Default>(
        &self,
        state: &mut S,
        general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, ExecutionError> {
        // TODO: uncomment once execute entry point has been implemented
        // let call = ExecuteEntryPoint.create();
        // let call_info = call.execute();
        //  actual_resources = calculate_tx_resources();
        let call = ExecutionEntryPoint::new(
            // contract_address
            self.contract_address.clone(),
            // calldata
            self.constructor_calldata.clone(),
            // entry_point_selector
            Felt::from_bytes_be(&calculate_sn_keccak(b"constructor")),
            // caller_address
            Address(0.into()),
            // entry_point_type
            EntryPointType::Constructor,
            // call_type
            None,
            // class_hash
            None,
        );

        let tx_execution_context = TransactionExecutionContext::new(
            Address(Felt::zero()),
            self.hash_value.clone(),
            Vec::new(),
            0,
            Felt::zero(),
            general_config.invoke_tx_max_n_steps,
            self.version,
        );

        let mut resources_manager = ExecutionResourcesManager::default();

        let call_info = call.execute(
            state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
        )?;

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(call_info.clone())],
            self.tx_type.clone(),
            state.count_actual_storage_changes(),
            None,
        )?;

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                None,
                Some(call_info),
                actual_resources,
                Some(self.tx_type.clone()),
            ),
        )
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
        starknet_storage::dict_storage::DictStorage,
    };
    use std::path::PathBuf;

    #[test]
    fn invoke_constructor_test() {
        // Instantiate CachedState
        let state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
        let mut state = CachedState::new(state_reader, None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        // Set contract_class
        let class_hash: [u8; 32] = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("tests/constructor.json")).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        let internal_deploy = InternalDeploy {
            hash_value: 0.into(),
            version: 0,
            contract_address: Address(1.into()),
            _contract_address_salt: Address(1111.into()),
            contract_hash: class_hash,
            constructor_calldata: vec![10.into()],
            tx_type: TransactionType::Deploy,
        };

        let result = internal_deploy
            ._apply_specific_concurrent_changes(state, StarknetGeneralConfig::default())
            .unwrap();
        dbg!(&result);
    }
}
