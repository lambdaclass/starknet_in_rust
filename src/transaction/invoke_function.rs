use super::{
    fee::{calculate_tx_fee, charge_fee},
    get_tx_version, Transaction,
};
use crate::{
    core::transaction_hash::{calculate_transaction_hash_common, TransactionHashPrefix},
    definitions::{
        block_context::{BlockContext, StarknetChainId},
        constants::{
            EXECUTE_ENTRY_POINT_SELECTOR, VALIDATE_ENTRY_POINT_SELECTOR, VALIDATE_RETDATA,
        },
        transaction_type::TransactionType,
    },
    execution::{
        execution_entry_point::{ExecutionEntryPoint, ExecutionResult},
        gas_usage::get_onchain_data_segment_length,
        os_usage::ESTIMATED_INVOKE_FUNCTION_STEPS,
        CallInfo, TransactionExecutionContext, TransactionExecutionInfo,
    },
    services::{
        api::contract_classes::{
            compiled_class::CompiledClass, deprecated_contract_class::EntryPointType,
        },
        eth_definitions::eth_gas_constants::SHARP_GAS_PER_MEMORY_WORD,
    },
    state::{
        cached_state::CachedState,
        state_api::{State, StateChangesCount, StateReader},
        ExecutionResourcesManager, StateDiff,
    },
    transaction::error::TransactionError,
    utils::{calculate_tx_resources, Address},
};
use cairo_vm::felt::Felt252;
use getset::Getters;
use num_traits::{One, Zero};
use std::{collections::HashMap, fmt::Debug};

/// Represents an InvokeFunction transaction in the starknet network.
#[derive(Debug, Getters, Clone)]
pub struct InvokeFunction {
    #[getset(get = "pub")]
    contract_address: Address,
    entry_point_selector: Felt252,
    #[allow(dead_code)]
    entry_point_type: EntryPointType,
    calldata: Vec<Felt252>,
    tx_type: TransactionType,
    version: Felt252,
    validate_entry_point_selector: Felt252,
    #[getset(get = "pub")]
    hash_value: Felt252,
    #[getset(get = "pub")]
    signature: Vec<Felt252>,
    max_fee: u128,
    nonce: Option<Felt252>,
    skip_validation: bool,
    skip_execute: bool,
    skip_fee_transfer: bool,
    skip_nonce_check: bool,
}

impl InvokeFunction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_address: Address,
        entry_point_selector: Felt252,
        max_fee: u128,
        version: Felt252,
        calldata: Vec<Felt252>,
        signature: Vec<Felt252>,
        chain_id: Felt252,
        nonce: Option<Felt252>,
    ) -> Result<Self, TransactionError> {
        let (entry_point_selector_field, additional_data) = preprocess_invoke_function_fields(
            entry_point_selector.clone(),
            nonce.clone(),
            version.clone(),
        )?;
        let hash_value = calculate_transaction_hash_common(
            TransactionHashPrefix::Invoke,
            version.clone(),
            &contract_address,
            entry_point_selector_field,
            &calldata,
            max_fee,
            chain_id,
            &additional_data,
        )?;

        InvokeFunction::new_with_tx_hash(
            contract_address,
            entry_point_selector,
            max_fee,
            version,
            calldata,
            signature,
            nonce,
            hash_value,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_tx_hash(
        contract_address: Address,
        entry_point_selector: Felt252,
        max_fee: u128,
        version: Felt252,
        calldata: Vec<Felt252>,
        signature: Vec<Felt252>,
        nonce: Option<Felt252>,
        hash_value: Felt252,
    ) -> Result<Self, TransactionError> {
        let version = get_tx_version(version);

        let validate_entry_point_selector = VALIDATE_ENTRY_POINT_SELECTOR.clone();

        Ok(InvokeFunction {
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
            skip_validation: false,
            skip_execute: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        })
    }

    /// Creates a `InvokeFunction` from a starknet api `InvokeTransaction`.
    pub fn from_invoke_transaction(
        tx: starknet_api::transaction::InvokeTransaction,
        chain_id: StarknetChainId,
    ) -> Result<Self, TransactionError> {
        match tx {
            starknet_api::transaction::InvokeTransaction::V0(v0) => convert_invoke_v0(v0, chain_id),
            starknet_api::transaction::InvokeTransaction::V1(v1) => convert_invoke_v1(v1, chain_id),
        }
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
            if self.version.is_zero() {
                Felt252::zero()
            } else {
                self.nonce.clone().ok_or(TransactionError::MissingNonce)?
            },
            n_steps,
            self.version.clone(),
        ))
    }

    /// Execute the validation entrypoint of the contract and returns the call info.
    /// ## Parameters:
    /// - state: A state that implements the [`State`] and [`StateReader`] traits.
    /// - resources_manager: the resources that are in use by the contract
    /// - block_context: The block's execution context
    pub(crate) fn run_validate_entrypoint<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        resources_manager: &mut ExecutionResourcesManager,
        block_context: &BlockContext,
    ) -> Result<Option<CallInfo>, TransactionError> {
        if self.entry_point_selector != *EXECUTE_ENTRY_POINT_SELECTOR {
            return Ok(None);
        }
        if self.version.is_zero() || self.skip_validation {
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
            0,
        );

        let ExecutionResult { call_info, .. } = call.execute(
            state,
            block_context,
            resources_manager,
            &mut self.get_execution_context(block_context.validate_max_n_steps)?,
            false,
            block_context.validate_max_n_steps,
        )?;

        // Validate the return data
        let class_hash = state.get_class_hash_at(&self.contract_address)?;
        let contract_class = state
            .get_contract_class(&class_hash)
            .map_err(|_| TransactionError::MissingCompiledClass)?;
        if let CompiledClass::Sierra(_) = contract_class {
            // The account contract class is a Cairo 1.0 contract; the `validate` entry point should
            // return `VALID`.
            if !call_info
                .as_ref()
                .map(|ci| ci.retdata == vec![VALIDATE_RETDATA.clone()])
                .unwrap_or_default()
            {
                return Err(TransactionError::WrongValidateRetdata);
            }
        }

        let call_info = verify_no_calls_to_other_contracts(&call_info)
            .map_err(|_| TransactionError::InvalidContractCall)?;

        Ok(Some(call_info))
    }

    /// Builds the transaction execution context and executes the entry point.
    /// Returns the CallInfo.
    fn run_execute_entrypoint<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        block_context: &BlockContext,
        resources_manager: &mut ExecutionResourcesManager,
        remaining_gas: u128,
    ) -> Result<ExecutionResult, TransactionError> {
        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.calldata.clone(),
            self.entry_point_selector.clone(),
            Address(Felt252::zero()),
            EntryPointType::External,
            None,
            None,
            remaining_gas,
        );
        call.execute(
            state,
            block_context,
            resources_manager,
            &mut self.get_execution_context(block_context.invoke_tx_max_n_steps)?,
            true,
            block_context.invoke_tx_max_n_steps,
        )
    }

    /// Execute a call to the cairo-vm using the accounts_validation.cairo contract to validate
    /// the contract that is being declared. Then it returns the transaction execution info of the run.
    /// ## Parameters
    /// - state: A state that implements the [`State`] and [`StateReader`] traits.
    /// - block_context: The block's execution context.
    /// - remaining_gas: The amount of gas that the transaction disposes.
    pub fn apply<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        block_context: &BlockContext,
        remaining_gas: u128,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let mut resources_manager = ExecutionResourcesManager::default();
        let validate_info = if self.skip_validation {
            None
        } else {
            self.run_validate_entrypoint(state, &mut resources_manager, block_context)?
        };

        // Execute transaction
        let ExecutionResult {
            call_info,
            revert_error,
            n_reverted_steps,
        } = if self.skip_execute {
            ExecutionResult::default()
        } else {
            self.run_execute_entrypoint(
                state,
                block_context,
                &mut resources_manager,
                remaining_gas,
            )?
        };
        let changes = state.count_actual_state_changes(Some((
            &block_context.starknet_os_config.fee_token_address,
            &self.contract_address,
        )))?;
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &vec![call_info.clone(), validate_info.clone()],
            self.tx_type,
            changes,
            None,
            n_reverted_steps,
        )?;
        let transaction_execution_info = TransactionExecutionInfo::new_without_fee_info(
            validate_info,
            call_info,
            revert_error,
            actual_resources,
            Some(self.tx_type),
        );
        Ok(transaction_execution_info)
    }

    /// Calculates actual fee used by the transaction using the execution info returned by apply(),
    /// then updates the transaction execution info with the data of the fee.
    /// ## Parameters
    /// - state: A state that implements the [`State`] and [`StateReader`] traits.
    /// - block_context: The block's execution context.
    /// - remaining_gas: The amount of gas that the transaction disposes.
    #[tracing::instrument(level = "debug", ret, err, skip(self, state, block_context), fields(
        tx_type = ?TransactionType::InvokeFunction,
        self.version = ?self.version,
        self.hash_value = ?self.hash_value,
        self.contract_address = ?self.contract_address,
        self.entry_point_selector = ?self.entry_point_selector,
        self.entry_point_type = ?self.entry_point_type,
    ))]
    pub fn execute<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        block_context: &BlockContext,
        remaining_gas: u128,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        if self.version != Felt252::one() && self.version != Felt252::zero() {
            return Err(TransactionError::UnsupportedTxVersion(
                "Invoke".to_string(),
                self.version.clone(),
                vec![0, 1],
            ));
        }

        if !self.skip_fee_transfer {
            self.check_fee_balance(state, block_context)?;
        }

        self.handle_nonce(state)?;

        let mut transactional_state = state.create_transactional();
        let mut tx_exec_info =
            self.apply(&mut transactional_state, block_context, remaining_gas)?;

        let actual_fee = calculate_tx_fee(
            &tx_exec_info.actual_resources,
            block_context.starknet_os_config.gas_price,
            block_context,
        )?;

        if let Some(revert_error) = tx_exec_info.revert_error.clone() {
            // execution error
            tx_exec_info = tx_exec_info.to_revert_error(&revert_error);
        } else if actual_fee > self.max_fee {
            // max_fee exceeded
            tx_exec_info = tx_exec_info.to_revert_error(
                format!(
                    "Calculated fee ({}) exceeds max fee ({})",
                    actual_fee, self.max_fee
                )
                .as_str(),
            );
        } else {
            state
                .apply_state_update(&StateDiff::from_cached_state(transactional_state.cache())?)?;
        }

        let mut tx_execution_context =
            self.get_execution_context(block_context.invoke_tx_max_n_steps)?;
        let (fee_transfer_info, actual_fee) = charge_fee(
            state,
            &tx_exec_info.actual_resources,
            block_context,
            self.max_fee,
            &mut tx_execution_context,
            self.skip_fee_transfer,
        )?;

        tx_exec_info.set_fee_info(actual_fee, fee_transfer_info);

        Ok(tx_exec_info)
    }

    fn handle_nonce<S: State + StateReader>(&self, state: &mut S) -> Result<(), TransactionError> {
        if self.version.is_zero() {
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
                if !self.skip_nonce_check && nonce != &current_nonce {
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

    fn check_fee_balance<S: State + StateReader>(
        &self,
        state: &mut S,
        block_context: &BlockContext,
    ) -> Result<(), TransactionError> {
        if self.max_fee.is_zero() {
            return Ok(());
        }
        let minimal_fee = self.estimate_minimal_fee(block_context)?;
        // Check max fee is at least the estimated constant overhead.
        if self.max_fee < minimal_fee {
            return Err(TransactionError::MaxFeeTooLow(self.max_fee, minimal_fee));
        }
        // Check that the current balance is high enough to cover the max_fee
        let (balance_low, balance_high) =
            state.get_fee_token_balance(block_context, self.contract_address())?;
        // The fee is at most 128 bits, while balance is 256 bits (split into two 128 bit words).
        if balance_high.is_zero() && balance_low < Felt252::from(self.max_fee) {
            return Err(TransactionError::MaxFeeExceedsBalance(
                self.max_fee,
                balance_low,
                balance_high,
            ));
        }
        Ok(())
    }

    fn estimate_minimal_fee(&self, block_context: &BlockContext) -> Result<u128, TransactionError> {
        let n_estimated_steps = ESTIMATED_INVOKE_FUNCTION_STEPS;
        let onchain_data_length = get_onchain_data_segment_length(&StateChangesCount {
            n_storage_updates: 1,
            n_class_hash_updates: 0,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 1,
        });
        let resources = HashMap::from([
            (
                "l1_gas_usage".to_string(),
                onchain_data_length * SHARP_GAS_PER_MEMORY_WORD,
            ),
            ("n_steps".to_string(), n_estimated_steps),
        ]);
        calculate_tx_fee(
            &resources,
            block_context.starknet_os_config.gas_price,
            block_context,
        )
    }

    // Simulation function

    pub fn create_for_simulation(
        &self,
        skip_validation: bool,
        skip_execute: bool,
        skip_fee_transfer: bool,
        ignore_max_fee: bool,
        skip_nonce_check: bool,
    ) -> Transaction {
        let tx = InvokeFunction {
            skip_validation,
            skip_execute,
            skip_fee_transfer,
            skip_nonce_check,
            max_fee: if ignore_max_fee {
                u128::MAX
            } else {
                self.max_fee
            },
            ..self.clone()
        };

        Transaction::InvokeFunction(tx)
    }
}

// ------------------------------------
//  Invoke internal functions utils
// ------------------------------------

pub fn verify_no_calls_to_other_contracts(
    call_info: &Option<CallInfo>,
) -> Result<CallInfo, TransactionError> {
    let call_info = call_info.clone().ok_or(TransactionError::CallInfoIsNone)?;
    let invoked_contract_address = call_info.contract_address.clone();
    for internal_call in call_info.gen_call_topology() {
        if internal_call.contract_address != invoked_contract_address {
            return Err(TransactionError::UnauthorizedActionOnValidate);
        }
    }
    Ok(call_info)
}

// Performs validation on fields related to function invocation transaction.
// InvokeFunction transaction.
// Deduces and returns fields required for hash calculation of

pub(crate) fn preprocess_invoke_function_fields(
    entry_point_selector: Felt252,
    nonce: Option<Felt252>,
    version: Felt252,
) -> Result<(Felt252, Vec<Felt252>), TransactionError> {
    if version.is_zero() {
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

// ----------------------------------
//      Try from starknet api
// ----------------------------------

fn convert_invoke_v0(
    value: starknet_api::transaction::InvokeTransactionV0,
    chain_id: StarknetChainId,
) -> Result<InvokeFunction, TransactionError> {
    let contract_address = Address(Felt252::from_bytes_be(
        value.contract_address.0.key().bytes(),
    ));
    let max_fee = value.max_fee.0;
    let entry_point_selector = Felt252::from_bytes_be(value.entry_point_selector.0.bytes());
    let nonce = None;

    let signature = value
        .signature
        .0
        .iter()
        .map(|f| Felt252::from_bytes_be(f.bytes()))
        .collect();
    let calldata = value
        .calldata
        .0
        .as_ref()
        .iter()
        .map(|f| Felt252::from_bytes_be(f.bytes()))
        .collect();

    InvokeFunction::new(
        contract_address,
        entry_point_selector,
        max_fee,
        Felt252::new(0),
        calldata,
        signature,
        chain_id.to_felt(),
        nonce,
    )
}

fn convert_invoke_v1(
    value: starknet_api::transaction::InvokeTransactionV1,
    chain_id: StarknetChainId,
) -> Result<InvokeFunction, TransactionError> {
    let contract_address = Address(Felt252::from_bytes_be(value.sender_address.0.key().bytes()));
    let max_fee = value.max_fee.0;
    let nonce = Felt252::from_bytes_be(value.nonce.0.bytes());
    let entry_point_selector = EXECUTE_ENTRY_POINT_SELECTOR.clone();

    let signature = value
        .signature
        .0
        .iter()
        .map(|f| Felt252::from_bytes_be(f.bytes()))
        .collect();
    let calldata = value
        .calldata
        .0
        .as_ref()
        .iter()
        .map(|f| Felt252::from_bytes_be(f.bytes()))
        .collect();

    InvokeFunction::new(
        contract_address,
        entry_point_selector,
        max_fee,
        Felt252::new(1),
        calldata,
        signature,
        chain_id.to_felt(),
        Some(nonce),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        services::api::contract_classes::{
            compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
        },
        state::cached_state::CachedState,
        state::in_memory_state_reader::InMemoryStateReader,
        utils::calculate_sn_keccak,
    };
    use cairo_lang_starknet::casm_contract_class::CasmContractClass;
    use num_traits::Num;
    use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};
    use starknet_api::{
        core::{ContractAddress, Nonce, PatriciaKey},
        hash::{StarkFelt, StarkHash},
        transaction::{Fee, InvokeTransaction, InvokeTransactionV1, TransactionSignature},
    };
    use std::{collections::HashMap, sync::Arc};

    #[test]
    fn test_from_invoke_transaction() {
        // https://starkscan.co/tx/0x05b6cf416d56e7c7c519b44e6d06a41657ff6c6a3f2629044fac395e6d200ac4
        // result 0x05b6cf416d56e7c7c519b44e6d06a41657ff6c6a3f2629044fac395e6d200ac4
        let tx = InvokeTransaction::V1(InvokeTransactionV1 {
            sender_address: ContractAddress(
                PatriciaKey::try_from(
                    StarkHash::try_from(
                        "0x00c4658311841a69ce121543af332622bc243cf5593fc4aaf822481c7b7f183d",
                    )
                    .unwrap(),
                )
                .unwrap(),
            ),
            max_fee: Fee(49000000000000),
            signature: TransactionSignature(vec![
                StarkFelt::try_from(
                    "0x18315db8eb360a82ea11f302d6a6a35a11b9df1dc220ec1376c4d4604770dd4",
                )
                .unwrap(),
                StarkFelt::try_from(
                    "0x5e8642259ac8e99c84cdf88c17385698150eb11dccfb3036ecc2b97c0903d27",
                )
                .unwrap(),
            ]),
            nonce: Nonce(StarkFelt::from(22u32)),
            calldata: starknet_api::transaction::Calldata(Arc::new(vec![
                StarkFelt::try_from("0x1").unwrap(),
                StarkFelt::try_from(
                    "0x0454f0bd015e730e5adbb4f080b075fdbf55654ff41ee336203aa2e1ac4d4309",
                )
                .unwrap(),
                StarkFelt::try_from(
                    "0x032a99297e1d12a9b91d4f90d5dd4b160d93c84a9e3b4daa916fec14ec852e05",
                )
                .unwrap(),
                StarkFelt::try_from(
                    "0x0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                StarkFelt::try_from(
                    "0x0000000000000000000000000000000000000000000000000000000000000002",
                )
                .unwrap(),
                StarkFelt::try_from(
                    "0x0000000000000000000000000000000000000000000000000000000000000002",
                )
                .unwrap(),
                StarkFelt::try_from(
                    "0x0383538353434346334616431626237363933663435643237376236313461663",
                )
                .unwrap(),
                StarkFelt::try_from(
                    "0x0393762666334373463313762393535303530383563613961323435643965666",
                )
                .unwrap(),
            ])),
        });

        let tx_sir = InvokeFunction::from_invoke_transaction(tx, StarknetChainId::MainNet).unwrap();
        assert_eq!(
            tx_sir.hash_value.to_str_radix(16),
            "5b6cf416d56e7c7c519b44e6d06a41657ff6c6a3f2629044fac395e6d200ac4"
        );
    }

    #[test]
    fn test_invoke_apply_without_fees() {
        let internal_invoke_function = InvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 0.into(),
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: Some(0.into()),
            skip_validation: false,
            skip_execute: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(Arc::new(state_reader), HashMap::new());

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(
                &class_hash,
                &CompiledClass::Deprecated(Arc::new(contract_class)),
            )
            .unwrap();

        let mut transactional = state.create_transactional();
        // Invoke result
        let result = internal_invoke_function
            .apply(&mut transactional, &BlockContext::default(), 0)
            .unwrap();
        state
            .apply_state_update(&StateDiff::from_cached_state(transactional.cache()).unwrap())
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
    fn test_invoke_execute() {
        let internal_invoke_function = InvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 0.into(),
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: Some(0.into()),
            skip_validation: false,
            skip_execute: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(Arc::new(state_reader), HashMap::new());

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(
                &class_hash,
                &CompiledClass::Deprecated(Arc::new(contract_class)),
            )
            .unwrap();

        let result = internal_invoke_function
            .execute(&mut state, &BlockContext::default(), 0)
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
        let internal_invoke_function = InvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: (*EXECUTE_ENTRY_POINT_SELECTOR).clone(),
            entry_point_type: EntryPointType::External,
            calldata: Vec::new(),
            tx_type: TransactionType::InvokeFunction,
            version: 0.into(),
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: Some(0.into()),
            skip_validation: false,
            skip_execute: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/amm.json").unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(Arc::new(state_reader), HashMap::new());

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(
                &class_hash,
                &CompiledClass::Deprecated(Arc::new(contract_class)),
            )
            .unwrap();

        let mut transactional = state.create_transactional();
        let expected_error =
            internal_invoke_function.apply(&mut transactional, &BlockContext::default(), 0);

        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::EntryPointNotFound
        );
    }

    #[test]
    fn test_apply_v0_with_no_nonce() {
        let internal_invoke_function = InvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 0.into(),
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: None,
            skip_validation: false,
            skip_execute: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(Arc::new(state_reader), HashMap::new());

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(
                &class_hash,
                &CompiledClass::Deprecated(Arc::new(contract_class)),
            )
            .unwrap();

        let mut transactional = state.create_transactional();
        // Invoke result
        let result = internal_invoke_function
            .apply(&mut transactional, &BlockContext::default(), 0)
            .unwrap();
        state
            .apply_state_update(&StateDiff::from_cached_state(transactional.cache()).unwrap())
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
    fn test_run_validate_entrypoint_nonce_is_none_should_fail() {
        let internal_invoke_function = InvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: (*EXECUTE_ENTRY_POINT_SELECTOR).clone(),
            entry_point_type: EntryPointType::External,
            calldata: Vec::new(),
            tx_type: TransactionType::InvokeFunction,
            version: 1.into(),
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: None,
            skip_validation: false,
            skip_execute: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/amm.json").unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(Arc::new(state_reader), HashMap::new());

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(
                &class_hash,
                &CompiledClass::Deprecated(Arc::new(contract_class)),
            )
            .unwrap();

        let mut transactional = state.create_transactional();
        // Invoke result
        let expected_error =
            internal_invoke_function.apply(&mut transactional, &BlockContext::default(), 0);

        assert!(expected_error.is_err());
        assert_matches!(expected_error.unwrap_err(), TransactionError::MissingNonce);
    }

    #[test]
    // Test fee calculation is done correctly but payment to sequencer fails due
    // to the token contract not being deployed
    fn test_invoke_with_non_deployed_fee_token_should_fail() {
        let contract_address = Address(0.into());

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        // Set contact_state
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address.clone(), nonce);

        let internal_invoke_function = InvokeFunction {
            contract_address,
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 1.into(),
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 1000,
            nonce: Some(0.into()),
            skip_validation: false,
            skip_execute: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        };

        let mut state = CachedState::new(Arc::new(state_reader), HashMap::new());

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(
                &class_hash,
                &CompiledClass::Deprecated(Arc::new(contract_class)),
            )
            .unwrap();

        let block_context = BlockContext::default();

        let result = internal_invoke_function.execute(&mut state, &block_context, 0);
        assert!(result.is_err());
        assert_matches!(
            result.unwrap_err(),
            TransactionError::MaxFeeExceedsBalance(_, _, _)
        );
    }

    #[test]
    fn test_execute_invoke_actual_fee_exceeded_max_fee_should_fail() {
        let max_fee = 5;
        let internal_invoke_function = InvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 1.into(),
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee,
            nonce: Some(0.into()),
            skip_validation: false,
            skip_execute: false,
            skip_fee_transfer: true,
            skip_nonce_check: false,
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(Arc::new(state_reader), HashMap::new());

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(
                &class_hash,
                &CompiledClass::Deprecated(Arc::new(contract_class)),
            )
            .unwrap();

        let mut block_context = BlockContext::default();
        block_context.starknet_os_config.gas_price = 1;

        let tx_info = internal_invoke_function
            .execute(&mut state, &block_context, 0)
            .unwrap();
        let expected_actual_fee = 2483;
        let expected_tx_info = tx_info.clone().to_revert_error(
            format!(
                "Calculated fee ({}) exceeds max fee ({})",
                expected_actual_fee, max_fee
            )
            .as_str(),
        );

        assert_eq_sorted!(tx_info, expected_tx_info);
    }

    #[test]
    fn test_execute_invoke_twice_should_fail() {
        let internal_invoke_function = InvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 1.into(),
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: Some(0.into()),
            skip_validation: false,
            skip_execute: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(Arc::new(state_reader), HashMap::new());

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(
                &class_hash,
                &CompiledClass::Deprecated(Arc::new(contract_class)),
            )
            .unwrap();

        internal_invoke_function
            .execute(&mut state, &BlockContext::default(), 0)
            .unwrap();

        let expected_error =
            internal_invoke_function.execute(&mut state, &BlockContext::default(), 0);

        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::InvalidTransactionNonce(..)
        )
    }

    #[test]
    fn test_execute_inovoke_nonce_missing_should_fail() {
        let internal_invoke_function = InvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            entry_point_type: EntryPointType::External,
            calldata: vec![1.into(), 1.into(), 10.into()],
            tx_type: TransactionType::InvokeFunction,
            version: 1.into(),
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: None,
            skip_validation: false,
            skip_execute: false,
            skip_fee_transfer: false,
            skip_nonce_check: false,
        };

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/fibonacci.json").unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(Arc::new(state_reader), HashMap::new());

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(
                &class_hash,
                &CompiledClass::Deprecated(Arc::new(contract_class)),
            )
            .unwrap();

        let expected_error =
            internal_invoke_function.execute(&mut state, &BlockContext::default(), 0);

        assert!(expected_error.is_err());
        assert_matches!(expected_error.unwrap_err(), TransactionError::MissingNonce)
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
            0.into(),
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

        let expected_error = verify_no_calls_to_other_contracts(&Some(call_info));

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
        let result =
            preprocess_invoke_function_fields(entry_point_selector.clone(), None, 0.into());

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
            1.into(),
        );
        assert!(expected_error.is_err());
        assert_matches!(
            expected_error.unwrap_err(),
            TransactionError::InvokeFunctionNonZeroMissingNonce
        )
    }

    #[test]
    fn invoke_version_one_with_no_nonce_with_query_base_should_fail() {
        let expected_error = preprocess_invoke_function_fields(
            Felt252::from_str_radix(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16,
            )
            .unwrap(),
            None,
            Into::<Felt252>::into(1),
        );
        assert!(expected_error.is_err());
    }

    #[test]
    fn test_reverted_transaction_wrong_entry_point() {
        let internal_invoke_function = InvokeFunction {
            contract_address: Address(0.into()),
            entry_point_selector: Felt252::from_bytes_be(&calculate_sn_keccak(b"factorial_")),
            entry_point_type: EntryPointType::External,
            calldata: vec![],
            tx_type: TransactionType::InvokeFunction,
            version: 0.into(),
            validate_entry_point_selector: 0.into(),
            hash_value: 0.into(),
            signature: Vec::new(),
            max_fee: 0,
            nonce: Some(0.into()),
            skip_validation: true,
            skip_execute: false,
            skip_fee_transfer: true,
            skip_nonce_check: false,
        };

        let mut state_reader = InMemoryStateReader::default();
        let class_hash = [1; 32];
        let program_data = include_bytes!("../../starknet_programs/cairo1/factorial.casm");
        let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);
        state_reader
            .class_hash_to_compiled_class_hash
            .insert(class_hash, class_hash);
        // last is necessary so the transactional state can cache the class

        let mut casm_contract_class_cache = HashMap::new();

        casm_contract_class_cache.insert(class_hash, CompiledClass::Casm(Arc::new(contract_class)));

        let mut state = CachedState::new(Arc::new(state_reader), casm_contract_class_cache);

        let state_before_execution = state.clone();

        let result = internal_invoke_function
            .execute(&mut state, &BlockContext::default(), 0)
            .unwrap();

        assert!(result.call_info.is_none());
        assert_eq!(
            result.revert_error,
            Some("Requested entry point was not found".to_string())
        );
        assert_eq_sorted!(
            state.cache.class_hash_writes,
            state_before_execution.cache.class_hash_writes
        );
        assert_eq_sorted!(
            state.cache.compiled_class_hash_writes,
            state_before_execution.cache.compiled_class_hash_writes
        );
        assert_eq_sorted!(
            state.cache.nonce_writes,
            state_before_execution.cache.nonce_writes
        );
        assert_eq_sorted!(
            state.cache.storage_writes,
            state_before_execution.cache.storage_writes
        );
        assert_eq_sorted!(
            state.cache.class_hash_to_compiled_class_hash,
            state_before_execution
                .cache
                .class_hash_to_compiled_class_hash
        );
    }

    #[test]
    fn invoke_wrong_version() {
        let chain_id = StarknetChainId::TestNet.to_felt();

        // declare tx
        let internal_declare = InvokeFunction::new(
            Address(Felt252::one()),
            Felt252::one(),
            9000,
            2.into(),
            vec![],
            vec![],
            chain_id,
            Some(Felt252::zero()),
        )
        .unwrap();
        let result = internal_declare.execute::<CachedState<InMemoryStateReader>>(
            &mut CachedState::default(),
            &BlockContext::default(),
            u128::MAX,
        );

        assert_matches!(
        result,
        Err(TransactionError::UnsupportedTxVersion(tx, ver, supp))
        if tx == "Invoke" && ver == 2.into() && supp == vec![0, 1]);
    }
}
