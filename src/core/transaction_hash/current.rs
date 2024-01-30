use crate::{
    transaction::{DataAvailabilityMode, ResourceBounds},
    utils::Address,
};
use cairo_vm::Felt252;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::{Num, ToBytes};
use starknet_crypto::FieldElement;

use super::TransactionHashPrefix;

// Current transaction hash functions (V3 txs)

/// Calculates the transaction hash in the StarkNet network - a unique identifier of the
/// transaction, for V3 transactions.
/// The transaction hash is a hash of the following information:
///     1. A prefix that depends on the transaction type.
///     2. The transaction's version.
///     3. Sender address.
///     4. A hash of the fee-related fields (see `_hash_fee_related_fields()`'s docstring).
///     5. A hash of the paymaster data.
///     6. The network's chain ID.
///     7. The transaction's nonce.
///     8. A concatenation of the nonce and fee data availability modes.
///     9. Transaction-specific additional data.
#[allow(clippy::too_many_arguments)]
pub fn calculate_transaction_hash_common(
    tx_hash_prefix: TransactionHashPrefix,
    version: Felt252,
    sender_address: &Address,
    chain_id: Felt252,
    nonce: Felt252,
    tx_type_specific_data: &[Felt252],
    tip: u64,
    paymaster_data: &[Felt252],
    nonce_data_availability_mode: DataAvailabilityMode,
    fee_data_availability_mode: DataAvailabilityMode,
    l1_resource_bounds: Option<ResourceBounds>,
    l2_resource_bounds: Option<ResourceBounds>,
) -> Felt252 {
    const DATA_AVAILABILITY_MODE_BITS: u64 = 32;

    let fee_fields_hash = hash_fee_related_fields(tip, &l1_resource_bounds, &l2_resource_bounds);

    let da_mode_concatenation: u64 = (Into::<u64>::into(nonce_data_availability_mode)
        << DATA_AVAILABILITY_MODE_BITS)
        + Into::<u64>::into(fee_data_availability_mode);

    let field_element = |f: Felt252| {
        // Conversion between two felt types shouldn't fail
        FieldElement::from_bytes_be(&f.to_bytes_be()).unwrap_or_default()
    };

    let mut data_to_hash: Vec<FieldElement> = vec![
        field_element(tx_hash_prefix.get_prefix()),
        field_element(version),
        field_element(sender_address.0),
        fee_fields_hash,
        starknet_crypto::poseidon_hash_many(
            &paymaster_data
                .iter()
                .map(|f| field_element(*f))
                .collect::<Vec<_>>(),
        ),
        field_element(chain_id),
        field_element(nonce),
        da_mode_concatenation.into(),
    ];
    data_to_hash.extend_from_slice(
        &tx_type_specific_data
            .iter()
            .map(|f| field_element(*f))
            .collect::<Vec<_>>(),
    );
    Felt252::from_bytes_be(&starknet_crypto::poseidon_hash_many(&data_to_hash).to_bytes_be())
}

// Calculates the hash of the fee related fields of a transaction:
//     1. The transaction's tip.
//     2. A concatenation of the resource name, max amount and max price per unit - for each entry
//         in the resource bounds, in the following order: L1_gas, L2_gas.
fn hash_fee_related_fields(
    tip: u64,
    l1_resource_bounds: &Option<ResourceBounds>,
    l2_resource_bounds: &Option<ResourceBounds>,
) -> FieldElement {
    const MAX_AMOUNT_BITS: u64 = 64;
    const MAX_PRICE_PER_UNIT_BITS: u64 = 128;
    const RESOURCE_VALUE_OFFSET: u64 = MAX_AMOUNT_BITS + MAX_PRICE_PER_UNIT_BITS;
    lazy_static! {
        static ref L1_GAS: BigUint = BigUint::from_str_radix(
            "0x00000000000000000000000000000000000000000000000000004c315f474153",
            16
        )
        .unwrap();
        static ref L2_GAS: BigUint = BigUint::from_str_radix(
            "0x00000000000000000000000000000000000000000000000000004c325f474153",
            16
        )
        .unwrap();
        static ref L1_GAS_SHL_RESOURCE_VALUE_OFFSET: FieldElement =
            FieldElement::from_byte_slice_be(&(&*L1_GAS << RESOURCE_VALUE_OFFSET).to_be_bytes())
                .unwrap();
        static ref L2_GAS_SHL_RESOURCE_VALUE_OFFSET: FieldElement =
            FieldElement::from_byte_slice_be(&(&*L1_GAS << RESOURCE_VALUE_OFFSET).to_be_bytes())
                .unwrap();
    };
    let mut data_to_hash: Vec<FieldElement> = vec![tip.into()];
    if let Some(resource_bounds) = l1_resource_bounds {
        data_to_hash.push(
            *L1_GAS_SHL_RESOURCE_VALUE_OFFSET
                + FieldElement::from(resource_bounds.max_amount << MAX_PRICE_PER_UNIT_BITS)
                + FieldElement::from(resource_bounds.max_price_per_unit),
        );
    }
    if let Some(resource_bounds) = l2_resource_bounds {
        data_to_hash.push(
            *L2_GAS_SHL_RESOURCE_VALUE_OFFSET
                + FieldElement::from(resource_bounds.max_amount << MAX_PRICE_PER_UNIT_BITS)
                + FieldElement::from(resource_bounds.max_price_per_unit),
        );
    }

    starknet_crypto::poseidon_hash_many(&data_to_hash)
}
