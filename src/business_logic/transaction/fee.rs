use super::error::TransactionError;
use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint, CallInfo, TransactionExecutionContext,
        },
        state::state_api::{State, StateReader},
        state::ExecutionResourcesManager,
    },
    definitions::{
        constants::TRANSFER_ENTRY_POINT_SELECTOR, general_config::StarknetGeneralConfig,
    },
};
use cairo_vm::felt::Felt252;
use num_traits::ToPrimitive;
use starknet_contract_class::EntryPointType;
use std::collections::HashMap;

// second element is the actual fee that the transaction uses
pub type FeeInfo = (Option<CallInfo>, u128);

/// Transfers the amount actual_fee from the caller account to the sequencer.
/// Returns the resulting CallInfo of the transfer call.
pub(crate) fn execute_fee_transfer<S: State + StateReader>(
    state: &mut S,
    general_config: &StarknetGeneralConfig,
    tx_context: &TransactionExecutionContext,
    actual_fee: u128,
) -> Result<CallInfo, TransactionError> {
    if actual_fee > tx_context.max_fee {
        return Err(TransactionError::FeeError(
            "Actual fee exceeded max fee.".to_string(),
        ));
    }

    let fee_token_address = general_config.starknet_os_config.fee_token_address.clone();

    let calldata = [
        general_config.block_info.sequencer_address.0.clone(),
        Felt252::from(actual_fee),
        0.into(),
    ]
    .to_vec();

    let fee_transfer_call = ExecutionEntryPoint::new(
        fee_token_address,
        calldata,
        TRANSFER_ENTRY_POINT_SELECTOR.clone(),
        tx_context.account_contract_address.clone(),
        EntryPointType::External,
        None,
        None,
        0,
    );

    let mut resources_manager = ExecutionResourcesManager::default();
    fee_transfer_call
        .execute(
            state,
            general_config,
            &mut resources_manager,
            tx_context,
            false,
        )
        .map_err(|_| TransactionError::FeeError("Fee transfer failure".to_string()))
}

// ----------------------------------------------------------------------------------------
/// Calculates the fee of a transaction given its execution resources.
/// We add the l1_gas_usage (which may include, for example, the direct cost of L2-to-L1
/// messages) to the gas consumed by Cairo resource and multiply by the L1 gas price.

pub fn calculate_tx_fee(
    resources: &HashMap<String, usize>,
    gas_price: u128,
    general_config: &StarknetGeneralConfig,
) -> Result<u128, TransactionError> {
    let gas_usage = resources
        .get(&"l1_gas_usage".to_string())
        .ok_or_else(|| TransactionError::FeeError("Invalid fee value".to_string()))?
        .to_owned();

    let l1_gas_by_cairo_usage = calculate_l1_gas_by_cairo_usage(general_config, resources)?;
    let total_l1_gas_usage = gas_usage.to_f64().unwrap() + l1_gas_by_cairo_usage;

    Ok(total_l1_gas_usage.ceil() as u128 * gas_price)
}

// ----------------------------------------------------------------------------------------
/// Calculates the L1 gas consumed when submitting the underlying Cairo program to SHARP.
/// I.e., returns the heaviest Cairo resource weight (in terms of L1 gas), as the size of
/// a proof is determined similarly - by the (normalized) largest segment.

pub(crate) fn calculate_l1_gas_by_cairo_usage(
    general_config: &StarknetGeneralConfig,
    cairo_resource_usage: &HashMap<String, usize>,
) -> Result<f64, TransactionError> {
    if !cairo_resource_usage
        .keys()
        .all(|k| k == "l1_gas_usage" || general_config.cairo_resource_fee_weights.contains_key(k))
    {
        return Err(TransactionError::ResourcesError);
    }

    // Convert Cairo usage to L1 gas usage.
    Ok(max_of_keys(
        cairo_resource_usage,
        &general_config.cairo_resource_fee_weights,
    ))
}

fn max_of_keys(cairo_rsc: &HashMap<String, usize>, weights: &HashMap<String, f64>) -> f64 {
    let mut max = 0.0_f64;
    for (k, v) in weights {
        let val = cairo_rsc.get(k).unwrap_or(&0).to_f64().unwrap_or(0.0_f64);
        max = f64::max(max, val * v);
    }
    max
}
