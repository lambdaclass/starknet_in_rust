use cairo_vm::felt::Felt252;
use getset::Getters;
use starknet_contract_class::EntryPointType;

use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint, TransactionExecutionContext,
            TransactionExecutionInfo,
        },
        fact_state::state::ExecutionResourcesManager,
        state::state_api::{State, StateReader},
        transaction::{error::TransactionError, fee::calculate_tx_fee},
    },
    core::transaction_hash::{calculate_transaction_hash_common, TransactionHashPrefix},
    definitions::{
        constants::L1_HANDLER_VERSION, general_config::StarknetGeneralConfig,
        transaction_type::TransactionType,
    },
    utils::{calculate_tx_resources, Address},
};

#[allow(dead_code)]
#[derive(Debug, Getters)]
pub struct L1Handler {
    #[getset(get = "pub")]
    hash_value: Felt252,
    #[getset(get = "pub")]
    contract_address: Address,
    entry_point_selector: Felt252,
    calldata: Vec<Felt252>,
    nonce: Option<Felt252>,
    paid_fee_on_l1: Option<Felt252>,
}

impl L1Handler {
    pub fn new(
        contract_address: Address,
        entry_point_selector: Felt252,
        calldata: Vec<Felt252>,
        nonce: Felt252,
        chain_id: Felt252,
        paid_fee_on_l1: Option<Felt252>,
    ) -> L1Handler {
        let hash_value = calculate_transaction_hash_common(
            TransactionHashPrefix::L1Handler,
            L1_HANDLER_VERSION,
            &contract_address,
            entry_point_selector.clone(),
            &calldata,
            0,
            chain_id,
            &[nonce.clone()],
        )
        .unwrap();

        L1Handler {
            hash_value,
            contract_address,
            entry_point_selector,
            calldata,
            nonce: Some(nonce),
            paid_fee_on_l1,
        }
    }

    /// Applies self to 'state' by executing the L1-handler entry point.
    pub fn execute<S>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
        remaining_gas: u128,
    ) -> Result<TransactionExecutionInfo, TransactionError>
    where
        S: State + StateReader,
    {
        let mut resources_manager = ExecutionResourcesManager::default();
        let entrypoint = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.calldata.clone(),
            self.entry_point_selector.clone(),
            Address(0.into()),
            EntryPointType::L1Handler,
            None,
            None,
            remaining_gas,
        );

        let call_info = entrypoint.execute(
            state,
            general_config,
            &mut resources_manager,
            &self.get_execution_context(general_config.invoke_tx_max_n_steps)?,
            false,
        )?;

        let changes = state.count_actual_storage_changes();
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(call_info.clone())],
            TransactionType::L1Handler,
            changes,
            Some(self.get_payload_size()),
        )?;

        // Enforce L1 fees.
        if general_config.enforce_l1_handler_fee {
            // Backward compatibility; Continue running the transaction even when
            // L1 handler fee is enforced, and paid_fee_on_l1 is None; If this is the case,
            // the transaction is an old transaction.
            if self.paid_fee_on_l1.is_some() {
                let required_fee = calculate_tx_fee(
                    &actual_resources,
                    general_config.starknet_os_config.gas_price,
                    general_config,
                )?;
                // For now, assert only that any amount of fee was paid.
                // The error message still indicates the required fee.
                // if we are here, means that self.paid_fee_on_l1 is Some(...)
                let paid_fee = self.paid_fee_on_l1.clone().unwrap();
                if paid_fee > 0.into() {
                    return Err(TransactionError::FeeError(format!(
                        "Insufficient fee was paid. Expected: {required_fee};\n got: {paid_fee}."
                    )));
                };
            }
        }

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                None,
                Some(call_info),
                actual_resources,
                Some(TransactionType::L1Handler),
            ),
        )
    }

    /// Returns the payload size of the corresponding L1-to-L2 message.
    pub fn get_payload_size(&self) -> usize {
        // The calldata includes the "from" field, which is not a part of the payload.
        // We thus subtract 1.
        self.calldata.len() - 1
    }

    /// Returns the execution context of the transaction.
    pub fn get_execution_context(
        &self,
        n_steps: u64,
    ) -> Result<TransactionExecutionContext, TransactionError> {
        Ok(TransactionExecutionContext::new(
            self.contract_address.clone(),
            self.hash_value.clone(),
            [].to_vec(),
            0,
            self.nonce.clone().ok_or(TransactionError::MissingNonce)?,
            n_steps,
            L1_HANDLER_VERSION,
        ))
    }
}
