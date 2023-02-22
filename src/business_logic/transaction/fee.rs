use super::error::TransactionError;
use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            gas_usage,
            objects::{CallInfo, TransactionExecutionContext},
        },
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::cached_state::CachedState,
    },
    definitions::general_config::{self, StarknetGeneralConfig},
    services::api::contract_class::EntryPointType,
};
use felt::{felt_str, Felt};
use num_traits::{Num, ToPrimitive};
use std::cmp;
use std::collections::{HashMap, HashSet};

// ----------------------------------------------------------------------------
/// Transfers the amount actual_fee from the caller account to the sequencer.
/// Returns the resulting CallInfo of the transfer call.

pub(crate) fn execute_fee_transfer(
    state: &mut CachedState<InMemoryStateReader>,
    general_config: StarknetGeneralConfig,
    tx_context: TransactionExecutionContext,
    actual_fee: u64,
) -> Result<CallInfo, TransactionError> {
    if actual_fee as u64 > tx_context.max_fee {
        return Err(TransactionError::FeeError(
            "Actual fee exceeded max fee.".to_string(),
        ));
    }

    let fee_token_address = general_config.starknet_os_config.fee_token_address.clone();

    let calldata = [
        general_config.block_info.sequencer_address.0.clone(),
        Felt::from(actual_fee),
        0.into(),
    ]
    .to_vec();

    // Value generated from `get_selector_from_name('TRANSFER_ENTRY_POINT_SELECTOR')`.
    let entry_point_selector =
        felt_str!("232670485425082704932579856502088130646006032362877466777181098476241604910");

    let fee_transfer_call = ExecutionEntryPoint::new(
        fee_token_address,
        calldata,
        entry_point_selector,
        tx_context.account_contract_address.clone(),
        EntryPointType::External,
        None,
        None,
    );

    let mut resources_manager = ExecutionResourcesManager::default();
    fee_transfer_call
        .execute(state, &general_config, &mut resources_manager, &tx_context)
        .map_err(|_| TransactionError::FeeError("Fee transfer failure".to_string()))
}

// ----------------------------------------------------------------------------------------
/// Calculates the fee of a transaction given its execution resources.
/// We add the l1_gas_usage (which may include, for example, the direct cost of L2-to-L1
/// messages) to the gas consumed by Cairo resource and multiply by the L1 gas price.

pub(crate) fn calculate_tx_fee(
    resources: HashMap<String, Felt>,
    gas_price: u64,
    general_config: &StarknetGeneralConfig,
) -> Result<u64, TransactionError> {
    let gas_usage = resources
        .get(&"l1_gas_usage".to_string())
        .ok_or_else(|| TransactionError::FeeError("Invalid fee value".to_string()))?
        .to_owned();

    let l1_gas_by_cairo_usage = calculate_l1_gas_by_cairo_usage(general_config, resources)?;
    let total_l1_gas_usage = gas_usage.to_f64().unwrap() + l1_gas_by_cairo_usage;

    Ok(total_l1_gas_usage.ceil() as u64 * gas_price)
}

// ----------------------------------------------------------------------------------------
/// Calculates the L1 gas consumed when submitting the underlying Cairo program to SHARP.
/// I.e., returns the heaviest Cairo resource weight (in terms of L1 gas), as the size of
/// a proof is determined similarly - by the (normalized) largest segment.

pub(crate) fn calculate_l1_gas_by_cairo_usage(
    general_config: &StarknetGeneralConfig,
    cairo_resource_usage: HashMap<String, Felt>,
) -> Result<f64, TransactionError> {
    // Ensure that every key in `general_config.cairo_resource_fee_weights` is present in
    // `cairo_resource_usage`.
    if !general_config
        .cairo_resource_fee_weights
        .iter()
        .map(|(k, _)| k.as_str())
        .all(|k| cairo_resource_usage.contains_key(k))
    {
        return Err(TransactionError::ResourcesError);
    }

    // Convert Cairo usage to L1 gas usage.
    Ok(max_of_keys(
        &cairo_resource_usage,
        &general_config.cairo_resource_fee_weights,
    ))
}

fn max_of_keys(cairo_rsc: &HashMap<String, Felt>, weights: &HashMap<String, f64>) -> f64 {
    let mut max = 0.0_f64;
    for (k, v) in weights {
        let val = cairo_rsc
            .get(k)
            .unwrap_or(&0.into())
            .to_f64()
            .unwrap_or(0.0_f64);
        max = f64::max(max, val * v);
    }
    max
}
