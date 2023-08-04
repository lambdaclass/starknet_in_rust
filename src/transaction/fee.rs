use super::error::TransactionError;
use crate::definitions::constants::{FEE_FACTOR, QUERY_VERSION_BASE};
use crate::execution::execution_entry_point::ExecutionResult;
use crate::execution::CallType;
use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;
use crate::state::cached_state::CachedState;
use crate::{
    definitions::{
        block_context::BlockContext,
        constants::{INITIAL_GAS_COST, TRANSFER_ENTRY_POINT_SELECTOR},
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, TransactionExecutionContext,
    },
    state::state_api::StateReader,
    state::ExecutionResourcesManager,
};
use cairo_vm::felt::Felt252;
use num_traits::{ToPrimitive, Zero};
use std::cmp::min;
use std::collections::HashMap;

// second element is the actual fee that the transaction uses
pub type FeeInfo = (Option<CallInfo>, u128);

/// Transfers the amount actual_fee from the caller account to the sequencer.
/// Returns the resulting CallInfo of the transfer call.
pub(crate) fn execute_fee_transfer<S: StateReader>(
    state: &mut CachedState<S>,
    block_context: &BlockContext,
    tx_execution_context: &mut TransactionExecutionContext,
    actual_fee: u128,
) -> Result<CallInfo, TransactionError> {
    if actual_fee > tx_execution_context.max_fee {
        return Err(TransactionError::ActualFeeExceedsMaxFee(
            actual_fee,
            tx_execution_context.max_fee,
        ));
    }

    let fee_token_address = block_context.starknet_os_config.fee_token_address.clone();

    let calldata = [
        block_context.block_info.sequencer_address.0.clone(),
        Felt252::from(actual_fee), // U256.low
        0.into(),                  // U256.high
    ]
    .to_vec();

    let fee_transfer_call = ExecutionEntryPoint::new(
        fee_token_address,
        calldata,
        TRANSFER_ENTRY_POINT_SELECTOR.clone(),
        tx_execution_context.account_contract_address.clone(),
        EntryPointType::External,
        Some(CallType::Call),
        None,
        INITIAL_GAS_COST,
    );

    let mut resources_manager = ExecutionResourcesManager::default();
    let ExecutionResult { call_info, .. } = fee_transfer_call
        .execute(
            state,
            block_context,
            &mut resources_manager,
            tx_execution_context,
            false,
            block_context.invoke_tx_max_n_steps,
        )
        .map_err(|e| TransactionError::FeeTransferError(Box::new(e)))?;

    call_info.ok_or(TransactionError::CallInfoIsNone)
}

// ----------------------------------------------------------------------------------------
/// Calculates the fee of a transaction given its execution resources.
/// We add the l1_gas_usage (which may include, for example, the direct cost of L2-to-L1
/// messages) to the gas consumed by Cairo resource and multiply by the L1 gas price.

pub fn calculate_tx_fee(
    resources: &HashMap<String, usize>,
    gas_price: u128,
    block_context: &BlockContext,
) -> Result<u128, TransactionError> {
    let gas_usage = resources
        .get(&"l1_gas_usage".to_string())
        .ok_or_else(|| TransactionError::FeeError("Invalid fee value".to_string()))?
        .to_owned();

    let l1_gas_by_cairo_usage = calculate_l1_gas_by_cairo_usage(block_context, resources)?;
    let total_l1_gas_usage = gas_usage.to_f64().unwrap() + l1_gas_by_cairo_usage;

    Ok(total_l1_gas_usage.ceil() as u128 * gas_price)
}

// ----------------------------------------------------------------------------------------
/// Calculates the L1 gas consumed when submitting the underlying Cairo program to SHARP.
/// I.e., returns the heaviest Cairo resource weight (in terms of L1 gas), as the size of
/// a proof is determined similarly - by the (normalized) largest segment.

pub(crate) fn calculate_l1_gas_by_cairo_usage(
    block_context: &BlockContext,
    cairo_resource_usage: &HashMap<String, usize>,
) -> Result<f64, TransactionError> {
    if !cairo_resource_usage
        .keys()
        .all(|k| k == "l1_gas_usage" || block_context.cairo_resource_fee_weights.contains_key(k))
    {
        return Err(TransactionError::ResourcesError);
    }

    // Convert Cairo usage to L1 gas usage.
    Ok(max_of_keys(
        cairo_resource_usage,
        &block_context.cairo_resource_fee_weights,
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

/// Calculates and charges the actual fee.
///
/// # Parameters:
/// - `state`: A [CachedState].
/// - `resources`: The resources that are in use by the contract
/// - `block_context`: The block's execution context.
/// - `max_fee`: The maximum fee that the transaction is allowed to charge.
/// - `tx_execution_context`: The transaction's execution context.
/// - `skip_fee_transfer`: Whether to skip the fee transfer.
///
pub fn charge_fee<S: StateReader>(
    state: &mut CachedState<S>,
    resources: &HashMap<String, usize>,
    block_context: &BlockContext,
    max_fee: u128,
    tx_execution_context: &mut TransactionExecutionContext,
    skip_fee_transfer: bool,
) -> Result<FeeInfo, TransactionError> {
    if max_fee.is_zero() {
        return Ok((None, 0));
    }

    let actual_fee = calculate_tx_fee(
        resources,
        block_context.starknet_os_config.gas_price,
        block_context,
    )?;

    // TODO: We need to be sure if we want to charge max_fee or actual_fee before failing.
    if actual_fee > max_fee {
        // TODO: Charge fee
        return Err(TransactionError::ActualFeeExceedsMaxFee(
            actual_fee, max_fee,
        ));
    }

    let actual_fee = if tx_execution_context.version != 0.into()
        && tx_execution_context.version != *QUERY_VERSION_BASE
    {
        min(actual_fee, max_fee) * FEE_FACTOR
    } else {
        actual_fee
    };

    let fee_transfer_info = if skip_fee_transfer {
        None
    } else {
        Some(execute_fee_transfer(
            state,
            block_context,
            tx_execution_context,
            actual_fee,
        )?)
    };

    Ok((fee_transfer_info, actual_fee))
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use crate::{
        definitions::block_context::BlockContext,
        execution::TransactionExecutionContext,
        state::{cached_state::CachedState, in_memory_state_reader::InMemoryStateReader},
        transaction::{error::TransactionError, fee::charge_fee},
    };

    #[test]
    fn test_charge_fee_v0_actual_fee_exceeds_max_fee_should_return_error() {
        let mut state = CachedState::new(Arc::new(InMemoryStateReader::default()), None, None);
        let mut tx_execution_context = TransactionExecutionContext::default();
        let mut block_context = BlockContext::default();
        block_context.starknet_os_config.gas_price = 1;
        let resources = HashMap::from([
            ("l1_gas_usage".to_string(), 200_usize),
            ("pedersen_builtin".to_string(), 10000_usize),
        ]);
        let max_fee = 100;
        let skip_fee_transfer = true;

        let result = charge_fee(
            &mut state,
            &resources,
            &block_context,
            max_fee,
            &mut tx_execution_context,
            skip_fee_transfer,
        )
        .unwrap_err();

        assert_matches!(result, TransactionError::ActualFeeExceedsMaxFee(_, _));
    }

    #[test]
    fn test_charge_fee_v1_actual_fee_exceeds_max_fee_should_return_error() {
        let mut state = CachedState::new(Arc::new(InMemoryStateReader::default()), None, None);
        let mut tx_execution_context = TransactionExecutionContext {
            version: 1.into(),
            ..Default::default()
        };
        let mut block_context = BlockContext::default();
        block_context.starknet_os_config.gas_price = 1;
        let resources = HashMap::from([
            ("l1_gas_usage".to_string(), 200_usize),
            ("pedersen_builtin".to_string(), 10000_usize),
        ]);
        let max_fee = 100;
        let skip_fee_transfer = true;

        let result = charge_fee(
            &mut state,
            &resources,
            &block_context,
            max_fee,
            &mut tx_execution_context,
            skip_fee_transfer,
        )
        .unwrap_err();

        assert_matches!(result, TransactionError::ActualFeeExceedsMaxFee(_, _));
    }
}
