use std::collections::HashMap;

use cairo_vm::felt::Felt252;
use num_traits::{ToPrimitive, Zero};

use crate::{
    definitions::{
        block_context::BlockContext,
        constants::{
            INITIAL_GAS_COST, QUERY_VERSION_BASE, SUPPORTED_VERSIONS, TRANSFER_ENTRY_POINT_SELECTOR,
        },
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, TransactionExecutionContext,
    },
    state::{
        state_api::{State, StateReader},
        ExecutionResourcesManager,
    },
    utils::Address,
    EntryPointType,
};

use super::error::TransactionError;

// second element is the actual fee that the transaction uses
pub type FeeInfo = (Option<CallInfo>, u128);

/// Transfers the amount actual_fee from the caller account to the sequencer.
/// Returns the resulting CallInfo of the transfer call.
pub(crate) fn execute_fee_transfer<S: State + StateReader>(
    state: &mut S,
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
        None,
        None,
        INITIAL_GAS_COST,
    );

    let mut resources_manager = ExecutionResourcesManager::default();
    let fee_transfer_exec = fee_transfer_call.execute(
        state,
        block_context,
        &mut resources_manager,
        tx_execution_context,
        false,
    );
    // TODO: Avoid masking the error from the fee transfer.
    fee_transfer_exec.map_err(|e| TransactionError::FeeTransferError(Box::new(e)))
}

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

pub fn verify_version(
    version: &Felt252,
    max_fee: u128,
    nonce: &Felt252,
    signature: &Vec<Felt252>,
) -> Result<(), TransactionError> {
    if !SUPPORTED_VERSIONS.contains(version) {
        return Err(TransactionError::UnsupportedVersion(version.to_string()));
    }

    if version == &0.into() {
        if max_fee != 0 {
            return Err(TransactionError::InvalidMaxFee);
        }
        if nonce != &0.into() {
            return Err(TransactionError::InvalidNonce);
        }
        if !signature.is_empty() {
            return Err(TransactionError::InvalidSignature);
        }
    }

    Ok(())
}

pub fn handle_nonce<S: State + StateReader>(
    transaction_nonce: &Felt252,
    version: &Felt252,
    address: &Address,
    state: &mut S,
) -> Result<(), TransactionError> {
    if version.is_zero() || *version == QUERY_VERSION_BASE.clone() {
        return Ok(());
    }

    // retrieve the contract's current nonce from the state
    let actual = state.get_nonce_at(address)?;
    let expected = transaction_nonce.clone();

    // check that the transaction nonce is the same as the one from the state
    if actual != expected {
        let address = address.clone();
        return Err(TransactionError::InvalidTransactionNonce {
            address,
            actual,
            expected,
        });
    }

    // increment the nonce for this contract.
    Ok(state.increment_nonce(address)?)
}

#[cfg(test)]
mod test {
    use crate::transaction::error::TransactionError;

    use super::verify_version;

    #[test]
    fn version_0_with_max_fee_0_nonce_0_and_empty_signature_should_return_ok() {
        let version = 0.into();
        let max_fee = 0;
        let nonce = 0.into();
        let signature = vec![];
        let result = verify_version(&version, max_fee, &nonce, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn version_1_should_return_ok() {
        let version = 1.into();
        let max_fee = 2;
        let nonce = 3.into();
        let signature = vec![5.into()];
        let result = verify_version(&version, max_fee, &nonce, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn version_2_should_return_ok() {
        let version = 2.into();
        let max_fee = 43;
        let nonce = 4.into();
        let signature = vec![6.into()];
        let result = verify_version(&version, max_fee, &nonce, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn version_3_should_fail() {
        let version = 3.into();
        let max_fee = 0;
        let nonce = 0.into();
        let signature = vec![];
        let result = verify_version(&version, max_fee, &nonce, &signature).unwrap_err();
        assert_matches!(result, TransactionError::UnsupportedVersion(_));
    }

    #[test]
    fn version_0_with_max_fee_greater_than_0_should_fail() {
        let version = 0.into();
        let max_fee = 1;
        let nonce = 0.into();
        let signature = vec![];
        let result = verify_version(&version, max_fee, &nonce, &signature).unwrap_err();
        assert_matches!(result, TransactionError::InvalidMaxFee);
    }

    #[test]
    fn version_0_with_nonce_greater_than_0_should_fail() {
        let version = 0.into();
        let max_fee = 0;
        let nonce = 1.into();
        let signature = vec![];
        let result = verify_version(&version, max_fee, &nonce, &signature).unwrap_err();
        assert_matches!(result, TransactionError::InvalidNonce);
    }

    #[test]
    fn version_0_with_non_empty_signature_should_fail() {
        let version = 0.into();
        let max_fee = 0;
        let nonce = 0.into();
        let signature = vec![2.into()];
        let result = verify_version(&version, max_fee, &nonce, &signature).unwrap_err();
        assert_matches!(result, TransactionError::InvalidSignature);
    }
}
