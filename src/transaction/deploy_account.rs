use super::common::*;
use super::Transaction;
use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;
use crate::utils::verify_no_calls_to_other_contracts;
use crate::{
    core::{
        errors::state_errors::StateError,
        transaction_hash::calculate_deploy_account_transaction_hash,
    },
    definitions::{
        block_context::BlockContext,
        constants::{
            CONSTRUCTOR_ENTRY_POINT_SELECTOR, INITIAL_GAS_COST,
            VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR,
        },
        transaction_type::TransactionType,
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, TransactionExecutionContext,
        TransactionExecutionInfo,
    },
    hash_utils::calculate_contract_address,
    services::api::{
        contract_class_errors::ContractClassError, contract_classes::compiled_class::CompiledClass,
    },
    state::state_api::{State, StateReader},
    state::ExecutionResourcesManager,
    syscalls::syscall_handler_errors::SyscallHandlerError,
    transaction::error::TransactionError,
    utils::{calculate_tx_resources, Address, ClassHash},
};
use cairo_vm::felt::Felt252;
use getset::Getters;
use num_traits::Zero;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSelector {
    pub contract_addresses: Vec<Address>,
    pub class_hashes: Vec<ClassHash>,
}

#[derive(Clone, Debug, Getters)]
pub struct DeployAccount {
    #[getset(get = "pub")]
    contract_address: Address,
    #[getset(get = "pub")]
    contract_address_salt: Felt252,
    #[getset(get = "pub")]
    class_hash: ClassHash,
    #[getset(get = "pub")]
    constructor_calldata: Vec<Felt252>,
    version: Felt252,
    nonce: Felt252,
    max_fee: u128,
    #[getset(get = "pub")]
    hash_value: Felt252,
    #[getset(get = "pub")]
    signature: Vec<Felt252>,
    skip_validate: bool,
    skip_execute: bool,
    skip_fee_transfer: bool,
}

impl DeployAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_hash: ClassHash,
        max_fee: u128,
        version: Felt252,
        nonce: Felt252,
        constructor_calldata: Vec<Felt252>,
        signature: Vec<Felt252>,
        contract_address_salt: Felt252,
        chain_id: Felt252,
    ) -> Result<Self, SyscallHandlerError> {
        let contract_address = Address(calculate_contract_address(
            &contract_address_salt,
            &Felt252::from_bytes_be(&class_hash),
            &constructor_calldata,
            Address(Felt252::zero()),
        )?);

        let hash_value = calculate_deploy_account_transaction_hash(
            version.clone(),
            &contract_address,
            Felt252::from_bytes_be(&class_hash),
            &constructor_calldata,
            max_fee,
            nonce.clone(),
            contract_address_salt.clone(),
            chain_id,
        )?;

        Ok(Self {
            contract_address,
            contract_address_salt,
            class_hash,
            constructor_calldata,
            version,
            nonce,
            max_fee,
            hash_value,
            signature,
            skip_execute: false,
            skip_validate: false,
            skip_fee_transfer: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_tx_hash(
        class_hash: ClassHash,
        max_fee: u128,
        version: Felt252,
        nonce: Felt252,
        constructor_calldata: Vec<Felt252>,
        signature: Vec<Felt252>,
        contract_address_salt: Felt252,
        hash_value: Felt252,
    ) -> Result<Self, SyscallHandlerError> {
        let contract_address = Address(calculate_contract_address(
            &contract_address_salt,
            &Felt252::from_bytes_be(&class_hash),
            &constructor_calldata,
            Address(Felt252::zero()),
        )?);

        Ok(Self {
            contract_address,
            contract_address_salt,
            class_hash,
            constructor_calldata,
            version,
            nonce,
            max_fee,
            hash_value,
            signature,
            skip_execute: false,
            skip_validate: false,
            skip_fee_transfer: false,
        })
    }

    pub fn get_state_selector(&self, _block_context: BlockContext) -> StateSelector {
        StateSelector {
            contract_addresses: vec![self.contract_address.clone()],
            class_hashes: vec![self.class_hash],
        }
    }

    pub fn execute<S>(
        &self,
        state: &mut S,
        block_context: &BlockContext,
    ) -> Result<TransactionExecutionInfo, TransactionError>
    where
        S: State + StateReader,
    {
        let mut tx_info = self.apply(state, block_context)?;

        let (fee_transfer_info, actual_fee) =
            self.charge_fee(state, &tx_info.actual_resources, block_context)?;
        tx_info.set_fee_info(actual_fee, fee_transfer_info);

        Ok(tx_info)
    }

    fn constructor_entry_points_empty(
        &self,
        contract_class: CompiledClass,
    ) -> Result<bool, StateError> {
        match contract_class {
            CompiledClass::Deprecated(class) => Ok(class
                .entry_points_by_type
                .get(&EntryPointType::Constructor)
                .ok_or(ContractClassError::NoneEntryPointType)?
                .is_empty()),
            CompiledClass::Casm(class) => Ok(class.entry_points_by_type.constructor.is_empty()),
        }
    }

    /// Execute a call to the cairo-vm using the accounts_validation.cairo contract to validate
    /// the contract that is being declared. Then it returns the transaction execution info of the run.
    fn apply<S>(
        &self,
        state: &mut S,
        block_context: &BlockContext,
    ) -> Result<TransactionExecutionInfo, TransactionError>
    where
        S: State + StateReader,
    {
        // check the transaction version
        verify_version(&self.version, self.max_fee, &self.nonce, &self.signature)?;

        // check the nonce
        handle_nonce(&self.nonce, &self.version, self.contract_address(), state)?;

        // run the validation entrypoint
        let mut resources_manager = ExecutionResourcesManager::default();
        let validate_info = if self.skip_validate {
            None
        } else {
            self.run_validate_entrypoint(state, &mut resources_manager, block_context)?
        };

        // get the account contract class from the state
        let contract_class = state.get_contract_class(&self.class_hash)?;

        // deploy the account contract in the calculated contract address.
        state.deploy_contract(self.contract_address.clone(), self.class_hash)?;

        // execute the constructor of the account.
        let constructor_call_info =
            self.handle_constructor(contract_class, state, block_context, &mut resources_manager)?;

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(constructor_call_info.clone()), validate_info.clone()],
            TransactionType::DeployAccount,
            state.count_actual_storage_changes(),
            None,
        )
        .map_err::<TransactionError, _>(|_| TransactionError::ResourcesCalculation)?;

        Ok(TransactionExecutionInfo::new_without_fee_info(
            validate_info,
            Some(constructor_call_info),
            actual_resources,
            Some(TransactionType::DeployAccount),
        ))
    }

    pub fn handle_constructor<S>(
        &self,
        contract_class: CompiledClass,
        state: &mut S,
        block_context: &BlockContext,
        resources_manager: &mut ExecutionResourcesManager,
    ) -> Result<CallInfo, TransactionError>
    where
        S: State + StateReader,
    {
        if self.constructor_entry_points_empty(contract_class)? {
            if !self.constructor_calldata.is_empty() {
                return Err(TransactionError::EmptyConstructorCalldata);
            }

            Ok(CallInfo::empty_constructor_call(
                self.contract_address.clone(),
                Address(Felt252::zero()),
                Some(self.class_hash),
            ))
        } else {
            self.run_constructor_entrypoint(state, block_context, resources_manager)
        }
    }

    pub fn run_constructor_entrypoint<S>(
        &self,
        state: &mut S,
        block_context: &BlockContext,
        resources_manager: &mut ExecutionResourcesManager,
    ) -> Result<CallInfo, TransactionError>
    where
        S: State + StateReader,
    {
        let entry_point = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.constructor_calldata.clone(),
            CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone(),
            Address(Felt252::zero()),
            EntryPointType::Constructor,
            None,
            None,
            INITIAL_GAS_COST,
        );

        if self.skip_execute {
            Err(TransactionError::InvalidContractCall)
        } else {
            let constructor_call_info = entry_point.execute(
                state,
                block_context,
                resources_manager,
                &mut self.get_execution_context(block_context.validate_max_n_steps),
                false,
            )?;
            verify_no_calls_to_other_contracts(&constructor_call_info)?;
            Ok(constructor_call_info)
        }
    }

    pub fn get_execution_context(&self, n_steps: u64) -> TransactionExecutionContext {
        TransactionExecutionContext::new(
            self.contract_address.clone(),
            self.hash_value.clone(),
            self.signature.clone(),
            self.max_fee,
            self.nonce.clone(),
            n_steps,
            self.version.clone(),
        )
    }

    pub fn run_validate_entrypoint<S>(
        &self,
        state: &mut S,
        resources_manager: &mut ExecutionResourcesManager,
        block_context: &BlockContext,
    ) -> Result<Option<CallInfo>, TransactionError>
    where
        S: State + StateReader,
    {
        if self.version.is_zero() {
            return Ok(None);
        }

        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            [
                Felt252::from_bytes_be(&self.class_hash),
                self.contract_address_salt.clone(),
            ]
            .into_iter()
            .chain(self.constructor_calldata.iter().cloned())
            .collect(),
            VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR.clone(),
            Address(Felt252::zero()),
            EntryPointType::External,
            None,
            None,
            INITIAL_GAS_COST,
        );

        let validate_call_info = call.execute(
            state,
            block_context,
            resources_manager,
            &mut self.get_execution_context(block_context.validate_max_n_steps),
            false,
        )?;

        verify_no_calls_to_other_contracts(&validate_call_info)?;

        Ok(Some(validate_call_info))
    }

    fn charge_fee<S>(
        &self,
        state: &mut S,
        resources: &HashMap<String, usize>,
        block_context: &BlockContext,
    ) -> Result<FeeInfo, TransactionError>
    where
        S: State + StateReader,
    {
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

    pub(crate) fn create_for_simulation(
        &self,
        skip_validate: bool,
        skip_execute: bool,
        skip_fee_transfer: bool,
    ) -> Transaction {
        let tx = DeployAccount {
            skip_validate,
            skip_execute,
            skip_fee_transfer,
            ..self.clone()
        };

        Transaction::DeployAccount(tx)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        core::{contract_address::compute_deprecated_class_hash, errors::state_errors::StateError},
        definitions::block_context::StarknetChainId,
        services::api::contract_classes::deprecated_contract_class::ContractClass,
        state::cached_state::CachedState,
        state::in_memory_state_reader::InMemoryStateReader,
        utils::felt_to_hash,
    };

    #[test]
    fn get_state_selector() {
        let path = PathBuf::from("starknet_programs/constructor.json");
        let contract = ContractClass::from_path(path).unwrap();

        let hash = compute_deprecated_class_hash(&contract).unwrap();
        let class_hash = felt_to_hash(&hash);

        let block_context = BlockContext::default();
        let mut _state = CachedState::new(
            InMemoryStateReader::default(),
            Some(Default::default()),
            None,
        );

        let internal_deploy = DeployAccount::new(
            class_hash,
            0,
            0.into(),
            0.into(),
            vec![10.into()],
            Vec::new(),
            0.into(),
            StarknetChainId::TestNet2.to_felt(),
        )
        .unwrap();

        let state_selector = internal_deploy.get_state_selector(block_context);

        assert_eq!(
            state_selector.contract_addresses,
            vec![internal_deploy.contract_address]
        );
        assert_eq!(state_selector.class_hashes, vec![class_hash]);
    }

    #[test]
    fn deploy_account_twice_should_fail() {
        let path = PathBuf::from("starknet_programs/constructor.json");
        let contract = ContractClass::from_path(path).unwrap();

        let hash = compute_deprecated_class_hash(&contract).unwrap();
        let class_hash = felt_to_hash(&hash);

        let block_context = BlockContext::default();
        let mut state = CachedState::new(
            InMemoryStateReader::default(),
            Some(Default::default()),
            None,
        );

        let deploy_account = DeployAccount::new(
            class_hash,
            0,
            0.into(),
            0.into(),
            vec![10.into()],
            Vec::new(),
            0.into(),
            StarknetChainId::TestNet2.to_felt(),
        )
        .unwrap();

        let deploy_account_error = DeployAccount::new(
            class_hash,
            0,
            0.into(),
            0.into(),
            vec![10.into()],
            Vec::new(),
            0.into(),
            StarknetChainId::TestNet2.to_felt(),
        )
        .unwrap();

        let class_hash = deploy_account.class_hash();
        state.set_contract_class(class_hash, &contract).unwrap();
        deploy_account.execute(&mut state, &block_context).unwrap();
        assert_matches!(
            deploy_account_error
                .execute(&mut state, &block_context)
                .unwrap_err(),
            TransactionError::State(StateError::ContractAddressUnavailable(..))
        )
    }

    #[test]
    #[should_panic]
    // Should panic at no calldata for constructor. Error managment not implemented yet.
    fn deploy_account_constructor_should_fail() {
        let path = PathBuf::from("starknet_programs/constructor.json");
        let contract = ContractClass::from_path(path).unwrap();

        let hash = compute_deprecated_class_hash(&contract).unwrap();
        let class_hash = felt_to_hash(&hash);

        let block_context = BlockContext::default();
        let mut state = CachedState::new(
            InMemoryStateReader::default(),
            Some(Default::default()),
            None,
        );

        let deploy_account = DeployAccount::new(
            class_hash,
            0,
            0.into(),
            0.into(),
            Vec::new(),
            Vec::new(),
            0.into(),
            StarknetChainId::TestNet2.to_felt(),
        )
        .unwrap();

        let class_hash = deploy_account.class_hash();
        state.set_contract_class(class_hash, &contract).unwrap();
        deploy_account.execute(&mut state, &block_context).unwrap();
    }
}
