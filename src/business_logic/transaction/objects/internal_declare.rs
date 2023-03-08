use crate::{
    business_logic::{
        execution::{
            error::ExecutionError,
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
    core::{
        contract_address::starknet_contract_address::compute_class_hash,
        transaction_hash::starknet_transaction_hash::calculate_declare_transaction_hash,
    },
    definitions::{
        constants::VALIDATE_DECLARE_ENTRY_POINT_NAME, general_config::StarknetGeneralConfig,
        transaction_type::TransactionType,
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{calculate_tx_resources, felt_to_hash, verify_no_calls_to_other_contracts, Address},
};
use felt::Felt;
use num_traits::Zero;
use std::collections::HashMap;

///  Represents an internal transaction in the StarkNet network that is a declaration of a Cairo
///  contract class.
pub(crate) struct InternalDeclare {
    pub(crate) class_hash: [u8; 32],
    pub(crate) sender_address: Address,
    pub(crate) tx_type: TransactionType,
    pub(crate) validate_entry_point_selector: Felt,
    pub(crate) version: u64,
    pub(crate) max_fee: u64,
    pub(crate) signature: Vec<Felt>,
    pub(crate) nonce: Felt,
    pub(crate) hash_value: Felt,
}

// ------------------------------------------------------------
//                        Functions
// ------------------------------------------------------------
impl InternalDeclare {
    pub fn new(
        contract_class: ContractClass,
        chain_id: Felt,
        sender_address: Address,
        max_fee: u64,
        version: u64,
        signature: Vec<Felt>,
        nonce: Felt,
    ) -> Result<Self, TransactionError> {
        let hash = compute_class_hash(&contract_class)?;
        let class_hash = felt_to_hash(&hash);

        let hash_value = calculate_declare_transaction_hash(
            contract_class,
            chain_id,
            sender_address.clone(),
            max_fee,
            version,
            nonce.clone(),
        )?;

        let validate_entry_point_selector = VALIDATE_DECLARE_ENTRY_POINT_NAME.clone();

        let internal_declare = InternalDeclare {
            class_hash,
            sender_address,
            tx_type: TransactionType::Declare,
            validate_entry_point_selector,
            version,
            max_fee,
            signature,
            nonce,
            hash_value,
        };

        internal_declare.verify_version()?;

        Ok(internal_declare)
    }

    pub fn get_calldata(&self) -> Vec<Felt> {
        let bytes = Felt::from_bytes_be(&self.class_hash);
        Vec::from([bytes])
    }

    pub fn verify_version(&self) -> Result<(), TransactionError> {
        // no need to check if its lesser than 0 because it is an usize
        if self.version > 0x8000_0000_0000_0000 {
            return Err(TransactionError::StarknetError(
                "The sender_address field in Declare transactions of version 0, sender should be 1"
                    .to_string(),
            ));
        }

        if !self.max_fee.is_zero() {
            return Err(TransactionError::StarknetError(
                "The max_fee field in Declare transactions of version 0 must be 0.".to_string(),
            ));
        }

        if !self.nonce.is_zero() {
            return Err(TransactionError::StarknetError(
                "The nonce field in Declare transactions of version 0 must be 0.".to_string(),
            ));
        }

        if !self.signature.len().is_zero() {
            return Err(TransactionError::StarknetError(
                "The signature field in Declare transactions must be an empty list.".to_string(),
            ));
        }
        Ok(())
    }

    /// Executes a call to the cairo-vm using the accounts_validation.cairo contract to validate
    /// the contract that is being declared. Then it returns the transaction execution info of the run.
    pub fn apply<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        self.verify_version()?;

        // validate transaction
        let mut resources_manager = ExecutionResourcesManager::default();
        let validate_info = self
            .run_validate_entrypoint(state, &mut resources_manager, general_config)
            .map_err(|e| TransactionError::RunValidationError(e.to_string()))?;

        let changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &vec![validate_info.clone()],
            TransactionType::Declare,
            changes,
            None,
        )
        .map_err(|_| TransactionError::ResourcesCalculationError)?;

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

    pub fn run_validate_entrypoint<S: Default + State + StateReader>(
        &self,
        state: &mut S,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: &StarknetGeneralConfig,
    ) -> Result<Option<CallInfo>, ExecutionError> {
        if self.version > 0x8000_0000_0000_0000 {
            return Ok(None);
        }

        let calldata = self.get_calldata();

        let entry_point = ExecutionEntryPoint::new(
            self.sender_address.clone(),
            calldata,
            self.validate_entry_point_selector.clone(),
            Address(Felt::zero()),
            EntryPointType::External,
            None,
            None,
        );

        let call_info = entry_point.execute(
            state,
            general_config,
            resources_manager,
            &self.get_execution_context(general_config.invoke_tx_max_n_steps),
        )?;

        verify_no_calls_to_other_contracts(&call_info)
            .map_err(|_| ExecutionError::UnauthorizedActionOnValidate)?;

        Ok(Some(call_info))
    }

    /// Calculates and charges the actual fee.
    pub fn charge_fee<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        resources: &HashMap<String, usize>,
        general_config: &StarknetGeneralConfig,
    ) -> Result<FeeInfo, TransactionError> {
        if self.max_fee.is_zero() {
            return Ok((None, 0));
        }

        let actual_fee = calculate_tx_fee(
            resources,
            general_config.starknet_os_config.gas_price,
            general_config,
        )?;

        let tx_context = self.get_execution_context(general_config.invoke_tx_max_n_steps);
        let fee_transfer_info =
            execute_fee_transfer(state, general_config, &tx_context, actual_fee)?;

        Ok((Some(fee_transfer_info), actual_fee))
    }

    fn handle_nonce<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
    ) -> Result<(), TransactionError> {
        if self.version == 0 {
            return Ok(());
        }

        let contract_address = &self.sender_address;
        let current_nonce = state.get_nonce_at(contract_address)?.to_owned();
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
    pub fn execute<S: Default + State + StateReader + Clone>(
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
}

// ---------------
//     Tests
// ---------------

#[cfg(test)]
mod tests {
    use felt::{felt_str, Felt};
    use num_traits::One;
    use std::{collections::HashMap, path::PathBuf};

    use crate::{
        business_logic::{
            execution::objects::{CallInfo, CallType, TransactionExecutionInfo},
            fact_state::{
                contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
            },
            state::cached_state::CachedState,
        },
        core::contract_address::starknet_contract_address::compute_class_hash,
        definitions::{
            constants::VALIDATE_DECLARE_ENTRY_POINT_NAME,
            general_config::{StarknetChainId, StarknetGeneralConfig},
            transaction_type::TransactionType,
        },
        services::api::contract_class::{ContractClass, EntryPointType},
        utils::{felt_to_hash, Address},
    };

    use super::InternalDeclare;

    #[test]
    fn declare_fibonacci() {
        // accounts contract class must be store before running declarartion of fibonacci
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::try_from(path).unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------
        let hash = compute_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);

        contract_class_cache.insert(class_hash, contract_class.clone());

        // store sender_address
        let sender_address = Address(1.into());
        // this is not conceptually correct as the sender address would be an
        // Account contract (not the contract that we are currently declaring)
        // but for testing reasons its ok
        let contract_state = ContractState::new(class_hash, 1.into(), HashMap::new());

        let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
        state_reader
            .contract_states
            .insert(sender_address, contract_state);

        let mut state = CachedState::new(state_reader, Some(contract_class_cache));

        //* ---------------------------------------
        //*    Test declare with previous data
        //* ---------------------------------------

        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let chain_id = StarknetChainId::TestNet.to_felt();

        // ----- calculate fib class hash ---------
        let hash = compute_class_hash(&fib_contract_class).unwrap();
        let fib_class_hash = felt_to_hash(&hash);

        // declare tx
        let internal_declare = InternalDeclare::new(
            fib_contract_class.clone(),
            chain_id,
            Address(1.into()),
            0,
            0,
            Vec::new(),
            0.into(),
        )
        .unwrap();

        // this simulate the setting done while declaring with starknet state

        state
            .contract_classes
            .as_mut()
            .unwrap()
            .insert(fib_class_hash, fib_contract_class);

        //* ---------------------------------------
        //              Expected result
        //* ---------------------------------------

        // Value generated from selector _validate_declare_
        let entry_point_selector = Some(VALIDATE_DECLARE_ENTRY_POINT_NAME.clone());

        let class_hash_felt = compute_class_hash(&contract_class).unwrap();
        let expected_class_hash = felt_to_hash(&class_hash_felt);

        // Calldata is the class hash represented as a Felt
        let calldata = [felt_str!(
            "3263750508471340057496742110279857589794844827005189048727502686976772849721"
        )]
        .to_vec();

        let validate_info = Some(CallInfo {
            caller_address: Address(0.into()),
            call_type: Some(CallType::Call),
            contract_address: Address(Felt::one()),
            entry_point_selector,
            entry_point_type: Some(EntryPointType::External),
            calldata,
            class_hash: Some(expected_class_hash),
            ..Default::default()
        });

        let mut actual_resources = HashMap::new();
        actual_resources.insert("l1_gas_usage".to_string(), 0);
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
                .apply(&mut state, &StarknetGeneralConfig::default())
                .unwrap(),
            transaction_exec_info
        );
    }
}
