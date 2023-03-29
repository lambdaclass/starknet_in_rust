use felt::Felt252;

use crate::{
    definitions::transaction_type::TransactionType,
    services::api::contract_class::ContractClass,
    utils::{Address, ClassHash},
};

pub struct InternalDeclareV2 {
    pub class_hash: ClassHash,
    pub sender_address: Address,
    pub tx_type: TransactionType,
    pub validate_entry_point_selector: Felt252,
    pub version: u64,
    pub max_fee: u64,
    pub signature: Vec<Felt252>,
    pub nonce: Felt252,
    pub hash_value: Felt252,
    pub contract_class: ContractClass,
}
impl InternalDeclareV2 {
    pub fn new(
        contract_class: ContractClass,
        chain_id: Felt252,
        sender_address: Address,
        max_fee: u64,
        version: u64,
        signature: Vec<Felt252>,
        nonce: Felt252,
    ) -> Result<Self, TransactionError> {
        let hash = compute_class_hash(&contract_class)?;
        let class_hash = felt_to_hash(&hash);

        let hash_value = calculate_declare_transaction_hash(
            &contract_class,
            chain_id,
            &sender_address,
            max_fee,
            version,
            nonce.clone(),
        )?;

        let validate_entry_point_selector = VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone();

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
            contract_class,
        };

        internal_declare.verify_version()?;

        Ok(internal_declare)
    }

    pub fn get_calldata(&self) -> Vec<Felt252> {
        let bytes = Felt252::from_bytes_be(&self.class_hash);
        Vec::from([bytes])
    }

    pub fn verify_version(&self) -> Result<(), TransactionError> {
        if self.version.is_zero() {
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
        let validate_info =
            self.run_validate_entrypoint(state, &mut resources_manager, general_config)?;

        let changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &vec![validate_info.clone()],
            TransactionType::Declare,
            changes,
            None,
        )
        .map_err(|_| TransactionError::ResourcesCalculation)?;

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
    ) -> Result<Option<CallInfo>, TransactionError> {
        if self.version == 0 {
            return Ok(None);
        }

        let calldata = self.get_calldata();

        let entry_point = ExecutionEntryPoint::new(
            self.sender_address.clone(),
            calldata,
            self.validate_entry_point_selector.clone(),
            Address(Felt252::zero()),
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
            .map_err(|_| TransactionError::UnauthorizedActionOnValidate)?;

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
        // Set contract class
        match state.get_contract_class(&self.class_hash) {
            Err(StateError::MissingClassHash()) => {
                // Class is undeclared; declare it.
                state.set_contract_class(&self.class_hash, &self.contract_class)?;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {
                // Class is already declared; cannot redeclare.
                return Err(TransactionError::ClassAlreadyDeclared(self.class_hash));
            }
        }

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
