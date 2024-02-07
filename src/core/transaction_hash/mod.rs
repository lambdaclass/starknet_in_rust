pub mod current;
pub mod deprecated;
use cairo_vm::Felt252;
use lazy_static::lazy_static;

use crate::{
    transaction::Address,
    transaction::{error::TransactionError, VersionSpecificAccountTxFields},
};

use super::errors::hash_errors::HashError;

#[derive(Debug)]
/// Enum representing the different types of transaction hash prefixes.
pub enum TransactionHashPrefix {
    Declare,
    Deploy,
    DeployAccount,
    Invoke,
    L1Handler,
}

lazy_static! {
    static ref DECLARE_TX_HASH_PREFIX: Felt252 =
        Felt252::from_dec_str("28258975365558885").unwrap();
    static ref DEPLOY_TX_HASH_PREFIX: Felt252 = Felt252::from_dec_str("110386840629113").unwrap();
    static ref DEPLOY_ACCOUNT_TX_HASH_PREFIX: Felt252 =
        Felt252::from_dec_str("2036277798190617858034555652763252").unwrap();
    static ref INVOKE_TX_HASH_PREFIX: Felt252 = Felt252::from_dec_str("115923154332517").unwrap();
    static ref L1_HANDLER_TX_HASH_PREFIX: Felt252 =
        Felt252::from_dec_str("510926345461491391292786").unwrap();
}

// Returns the associated prefix value for a given transaction type.
impl TransactionHashPrefix {
    fn get_prefix(&self) -> Felt252 {
        match self {
            TransactionHashPrefix::Declare => *DECLARE_TX_HASH_PREFIX,
            TransactionHashPrefix::Deploy => *DEPLOY_TX_HASH_PREFIX,
            TransactionHashPrefix::DeployAccount => *DEPLOY_ACCOUNT_TX_HASH_PREFIX,
            TransactionHashPrefix::Invoke => *INVOKE_TX_HASH_PREFIX,
            TransactionHashPrefix::L1Handler => *L1_HANDLER_TX_HASH_PREFIX,
        }
    }
}

/// Calculate the hash for a DeployAccount transaction.
/// Uses the older pedersen version for deprecated account tx fields and the newer poseidon version for current account tx fields
#[allow(clippy::too_many_arguments)]
pub fn calculate_deploy_account_transaction_hash(
    version: Felt252,
    nonce: Felt252,
    contract_address: &Address,
    salt: Felt252,
    class_hash: Felt252,
    constructor_calldata: &[Felt252],
    chain_id: Felt252,
    account_tx_fields: &VersionSpecificAccountTxFields,
) -> Result<Felt252, HashError> {
    match account_tx_fields {
        VersionSpecificAccountTxFields::Deprecated(max_fee) => {
            deprecated::deprecated_calculate_deploy_account_transaction_hash(
                version,
                contract_address,
                class_hash,
                constructor_calldata,
                *max_fee,
                nonce,
                salt,
                chain_id,
            )
        }
        VersionSpecificAccountTxFields::Current(fields) => {
            Ok(current::calculate_deploy_account_transaction_hash(
                version,
                nonce,
                contract_address,
                fields.nonce_data_availability_mode,
                fields.fee_data_availability_mode,
                &Some(fields.l1_resource_bounds.clone()),
                &fields.l2_resource_bounds,
                fields.tip,
                &fields.paymaster_data,
                salt,
                class_hash,
                constructor_calldata,
                chain_id,
            ))
        }
    }
}

/// Calculate the hash for a Declare transaction of version 2+.
/// Uses the older pedersen version for deprecated account tx fields and the newer poseidon version for current account tx fields
pub fn calculate_declare_transaction_hash(
    sierra_class_hash: Felt252,
    compiled_class_hash: Felt252,
    version: Felt252,
    nonce: Felt252,
    sender_address: &Address,
    chain_id: Felt252,
    account_tx_fields: &VersionSpecificAccountTxFields,
) -> Result<Felt252, HashError> {
    match account_tx_fields {
        VersionSpecificAccountTxFields::Deprecated(max_fee) => {
            deprecated::deprecated_calculate_declare_transaction_hash(
                sierra_class_hash,
                compiled_class_hash,
                chain_id,
                sender_address,
                *max_fee,
                version,
                nonce,
            )
        }
        VersionSpecificAccountTxFields::Current(fields) => {
            Ok(current::calculate_declare_transaction_hash(
                sierra_class_hash,
                compiled_class_hash,
                chain_id,
                sender_address,
                version,
                nonce,
                fields.nonce_data_availability_mode,
                fields.fee_data_availability_mode,
                &Some(fields.l1_resource_bounds.clone()),
                &fields.l2_resource_bounds,
                fields.tip,
                &fields.paymaster_data,
                &fields.account_deployment_data,
            ))
        }
    }
}

/// Calculate the hash for a DeployAccount transaction.
/// Uses the older pedersen version for deprecated account tx fields and the newer poseidon version for current account tx fields
pub fn calculate_invoke_transaction_hash(
    chain_id: Felt252,
    contract_address: &Address,
    entry_point_selector: Felt252,
    version: Felt252,
    nonce: Option<Felt252>,
    calldata: &[Felt252],
    account_tx_fields: &VersionSpecificAccountTxFields,
) -> Result<Felt252, TransactionError> {
    match account_tx_fields {
        VersionSpecificAccountTxFields::Deprecated(max_fee) => {
            deprecated::deprecated_calculate_invoke_transaction_hash(
                chain_id,
                contract_address,
                entry_point_selector,
                *max_fee,
                version,
                nonce,
                calldata,
            )
        }
        VersionSpecificAccountTxFields::Current(fields) => {
            Ok(current::calculate_invoke_transaction_hash(
                version,
                nonce.unwrap_or_default(),
                contract_address,
                fields.nonce_data_availability_mode,
                fields.fee_data_availability_mode,
                &Some(fields.l1_resource_bounds.clone()),
                &fields.l2_resource_bounds,
                fields.tip,
                &fields.paymaster_data,
                calldata,
                &fields.account_deployment_data,
                chain_id,
            ))
        }
    }
}
