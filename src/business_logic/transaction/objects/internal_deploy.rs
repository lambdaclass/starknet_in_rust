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
    definitions::{general_config::StarknetGeneralConfig, transaction_type::TransactionType},
    hash_utils::calculate_contract_address,
    services::api::contract_class::{ContractClass, EntryPointType},
    starkware_utils::starkware_errors::StarkwareError,
    utils::{calculate_tx_resources, felt_to_hash, Address, ClassHash},
};
use felt::{felt_str, Felt};
use num_traits::Zero;

pub struct InternalDeploy {
    pub(crate) hash_value: Felt,
    pub(crate) version: u64,
    pub(crate) contract_address: Address,
    pub(crate) _contract_address_salt: Address,
    pub(crate) contract_hash: ClassHash,
    pub(crate) constructor_calldata: Vec<Felt>,
    pub(crate) tx_type: TransactionType,
}

impl InternalDeploy {
    pub fn new(
        contract_address_salt: Address,
        contract_class: ContractClass,
        constructor_calldata: Vec<Felt>,
        chain_id: Felt,
        version: u64,
    ) -> Result<Self, SyscallHandlerError> {
        let class_hash = compute_class_hash(&contract_class)
            .map_err(|_| SyscallHandlerError::ErrorComputingHash)?;

        let contract_hash: ClassHash = felt_to_hash(&class_hash);
        let contract_address = Address(calculate_contract_address(
            &contract_address_salt,
            &class_hash,
            &constructor_calldata,
            Address(Felt::zero()),
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
        _general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, StarkwareError> {
        state.deploy_contract(self.contract_address.clone(), self.contract_hash)?;
        let class_hash: ClassHash = self.contract_hash;
        state.get_contract_class(&class_hash)?;
        self.handle_empty_constructor(state)
    }

    pub fn handle_empty_constructor<T: Default + State + StateReader + Clone>(
        &self,
        state: &mut T,
    ) -> Result<TransactionExecutionInfo, StarkwareError> {
        if self.constructor_calldata.is_empty() {
            return Err(StarkwareError::TransactionFailed);
        }

        let class_hash: ClassHash = self.contract_hash;
        let call_info = CallInfo::empty_constructor_call(
            self.contract_address.clone(),
            Address(Felt::zero()),
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

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn invoke_constructor<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        general_config: StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let entry_point_selector = felt_str!(
            "1159040026212278395030414237414753050475174923702621880048416706425641521556"
        );
        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.constructor_calldata.clone(),
            entry_point_selector,
            Address(Felt::zero()),
            EntryPointType::Constructor,
            None,
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
