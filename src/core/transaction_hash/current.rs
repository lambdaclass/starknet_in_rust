use std::str::FromStr;

use crate::{
    transaction::{DataAvailabilityMode, ResourceBounds},
    utils::Address,
};
use cairo_vm::Felt252;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::ToBytes;
use starknet_crypto::{poseidon_hash_many, FieldElement};

use super::TransactionHashPrefix;

// Current transaction hash functions (V3 txs)

/// Calculates the transaction hash in the StarkNet network - a unique identifier of the
/// transaction, for V3 transactions.
/// The transaction hash is a hash of the following information:
///     1. A prefix that depends on the transaction type.
///     2. The transaction's version.
///     3. Sender address.
///     4. A hash of the fee-related fields (see `hash_fee_related_fields()`'s docstring).
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
    l1_resource_bounds: &Option<ResourceBounds>,
    l2_resource_bounds: &Option<ResourceBounds>,
) -> Felt252 {
    const DATA_AVAILABILITY_MODE_BITS: u64 = 32;

    let fee_fields_hash = hash_fee_related_fields(tip, l1_resource_bounds, l2_resource_bounds);

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
// If either l1_resource_bounds or l2_resource_bounds is None the default value will be used (max_amount = 0, max_price_per_unit = 0)
fn hash_fee_related_fields(
    tip: u64,
    l1_resource_bounds: &Option<ResourceBounds>,
    l2_resource_bounds: &Option<ResourceBounds>,
) -> FieldElement {
    const MAX_AMOUNT_BITS: u64 = 64;
    const MAX_PRICE_PER_UNIT_BITS: u64 = 128;
    const RESOURCE_VALUE_OFFSET: u64 = MAX_AMOUNT_BITS + MAX_PRICE_PER_UNIT_BITS;
    lazy_static! {
        static ref L1_GAS: BigUint = BigUint::from_str("83774935613779",).unwrap();
        static ref L2_GAS: BigUint = BigUint::from_str("83779230581075",).unwrap();
        static ref L1_GAS_SHL_RESOURCE_VALUE_OFFSET: FieldElement =
            FieldElement::from_byte_slice_be(&(&*L1_GAS << RESOURCE_VALUE_OFFSET).to_be_bytes())
                .unwrap();
        static ref L2_GAS_SHL_RESOURCE_VALUE_OFFSET: FieldElement =
            FieldElement::from_byte_slice_be(&(&*L2_GAS << RESOURCE_VALUE_OFFSET).to_be_bytes())
                .unwrap();
    };

    let push_resource_bounds = |data_to_hash: &mut Vec<FieldElement>,
                                resource_val_shifted: FieldElement,
                                resource_bounds: &ResourceBounds| {
        data_to_hash.push(
            resource_val_shifted
                + FieldElement::from_byte_slice_be(
                    &(BigUint::from(resource_bounds.max_amount) << MAX_PRICE_PER_UNIT_BITS)
                        .to_be_bytes(),
                )
                .unwrap_or_default()
                + FieldElement::from(resource_bounds.max_price_per_unit),
        );
    };

    let mut data_to_hash: Vec<FieldElement> = vec![tip.into()];
    push_resource_bounds(
        &mut data_to_hash,
        *L1_GAS_SHL_RESOURCE_VALUE_OFFSET,
        &l1_resource_bounds.clone().unwrap_or_default(),
    );
    push_resource_bounds(
        &mut data_to_hash,
        *L2_GAS_SHL_RESOURCE_VALUE_OFFSET,
        &l2_resource_bounds.clone().unwrap_or_default(),
    );

    starknet_crypto::poseidon_hash_many(&data_to_hash)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn calculate_deploy_account_transaction_hash(
    version: Felt252,
    nonce: Felt252,
    contract_address: &Address,
    nonce_data_availability_mode: DataAvailabilityMode,
    fee_data_availability_mode: DataAvailabilityMode,
    l1_resource_bounds: &Option<ResourceBounds>,
    l2_resource_bounds: &Option<ResourceBounds>,
    tip: u64,
    paymaster_data: &[Felt252],
    salt: Felt252,
    class_hash: Felt252,
    constructor_calldata: &[Felt252],
    chain_id: Felt252,
) -> Felt252 {
    let deploy_account_specific_data =
        vec![poseidon_hash_array(constructor_calldata), class_hash, salt];
    calculate_transaction_hash_common(
        TransactionHashPrefix::DeployAccount,
        version,
        contract_address,
        chain_id,
        nonce,
        &deploy_account_specific_data,
        tip,
        paymaster_data,
        nonce_data_availability_mode,
        fee_data_availability_mode,
        l1_resource_bounds,
        l2_resource_bounds,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn calculate_declare_v2_transaction_hash(
    sierra_class_hash: Felt252,
    compiled_class_hash: Felt252,
    chain_id: Felt252,
    sender_address: &Address,
    version: Felt252,
    nonce: Felt252,
    nonce_data_availability_mode: DataAvailabilityMode,
    fee_data_availability_mode: DataAvailabilityMode,
    l1_resource_bounds: &Option<ResourceBounds>,
    l2_resource_bounds: &Option<ResourceBounds>,
    tip: u64,
    paymaster_data: &[Felt252],
    account_deployment_data: &[Felt252],
) -> Felt252 {
    let declare_specific_data = vec![
        poseidon_hash_array(account_deployment_data),
        sierra_class_hash,
        compiled_class_hash,
    ];
    calculate_transaction_hash_common(
        TransactionHashPrefix::Declare,
        version,
        sender_address,
        chain_id,
        nonce,
        &declare_specific_data,
        tip,
        paymaster_data,
        nonce_data_availability_mode,
        fee_data_availability_mode,
        l1_resource_bounds,
        l2_resource_bounds,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn calculate_invoke_transaction_hash(
    version: Felt252,
    nonce: Felt252,
    sender_address: &Address,
    nonce_data_availability_mode: DataAvailabilityMode,
    fee_data_availability_mode: DataAvailabilityMode,
    l1_resource_bounds: &Option<ResourceBounds>,
    l2_resource_bounds: &Option<ResourceBounds>,
    tip: u64,
    paymaster_data: &[Felt252],
    calldata: &[Felt252],
    account_deployment_data: &[Felt252],
    chain_id: Felt252,
) -> Felt252 {
    let invoke_specific_data = vec![
        poseidon_hash_array(account_deployment_data),
        poseidon_hash_array(calldata),
    ];

    calculate_transaction_hash_common(
        TransactionHashPrefix::Invoke,
        version,
        sender_address,
        chain_id,
        nonce,
        &invoke_specific_data,
        tip,
        paymaster_data,
        nonce_data_availability_mode,
        fee_data_availability_mode,
        l1_resource_bounds,
        l2_resource_bounds,
    )
}

fn poseidon_hash_array(data: &[Felt252]) -> Felt252 {
    Felt252::from_bytes_be(
        &poseidon_hash_many(
            &data
                .iter()
                .map(|f| FieldElement::from_bytes_be(&f.to_bytes_be()).unwrap_or_default())
                .collect::<Vec<_>>(),
        )
        .to_bytes_be(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definitions::block_context::StarknetChainId;

    #[test]
    fn calculate_invoke_hash_test() {
        // Transaction data taken from TestNet tx 0x75eb08d4f3eb099797635fbc3a0fa2c197a33ebc5c0546144d04e8043e05ee
        let tx_hash = calculate_invoke_transaction_hash(
            Felt252::THREE,
            Felt252::from_hex("0x1091e").unwrap(),
            &Address(
                Felt252::from_hex(
                    "0x35acd6dd6c5045d18ca6d0192af46b335a5402c02d41f46e4e77ea2c951d9a3",
                )
                .unwrap(),
            ),
            DataAvailabilityMode::L1,
            DataAvailabilityMode::L1,
            &Some(ResourceBounds {
                max_amount: 0x61a80,
                max_price_per_unit: 0x5af3107a4000,
            }),
            &Some(ResourceBounds::default()),
            0,
            &[],
            &vec![
                Felt252::from_hex("0x1").unwrap(),
                Felt252::from_hex(
                    "0x3fe8e4571772bbe0065e271686bd655efd1365a5d6858981e582f82f2c10313",
                )
                .unwrap(),
                Felt252::from_hex(
                    "0x31aafc75f498fdfa7528880ad27246b4c15af4954f96228c9a132b328de1c92",
                )
                .unwrap(),
                Felt252::from_hex("0x6").unwrap(),
                Felt252::from_hex(
                    "0x7b72968a3461c83ef80837f10274d408d0fa5944089bcc24b6507e1fe9cfebd",
                )
                .unwrap(),
                Felt252::from_hex("0x3").unwrap(),
                Felt252::from_hex(
                    "0x1533c867cfca1edc4d18e8bd1f8fdb570d5ba6e6c0d08c569de0d20e7c7d5c6",
                )
                .unwrap(),
                Felt252::from_hex(
                    "0x2d65735f9d358e2c9c07784597fa5c161ddafde39c06e97e65f8939d2ab0d0c",
                )
                .unwrap(),
                Felt252::from_hex(
                    "0x380a081ef58fdbf8afde92eecac79f3eccc3f4cac4ef940310320c15bccf4c9",
                )
                .unwrap(),
                Felt252::from_hex(
                    "0x3f2741161d2ea121fbdf96bf8a60e0d6fc8fc04ec48a28d77ccb7a3890f7301",
                )
                .unwrap(),
            ],
            &[],
            StarknetChainId::TestNet.to_felt(),
        );

        assert_eq!(
            tx_hash,
            Felt252::from_hex("0x75eb08d4f3eb099797635fbc3a0fa2c197a33ebc5c0546144d04e8043e05ee")
                .unwrap()
        )
    }

    #[test]
    fn calculate_declare_hash_test() {
        // Transaction data taken from TestNet tx 0x75eb08d4f3eb099797635fbc3a0fa2c197a33ebc5c0546144d04e8043e05ee
        let tx_hash = calculate_deploy_account_transaction_hash(
            Felt252::THREE,
            Felt252::ZERO,
            &Address(
                Felt252::from_hex(
                    "0x04e3187459e17c3c196faeae49616f3e8e1a60a0b7d621b953f9b347b093ecab",
                )
                .unwrap(),
            ),
            DataAvailabilityMode::L1,
            DataAvailabilityMode::L1,
            &Some(ResourceBounds {
                max_amount: 0x137d,
                max_price_per_unit: 0x1ad85ddc6,
            }),
            &Some(ResourceBounds::default()),
            0,
            &[],
            Felt252::from_hex("0x7794e240544f56f345118c67c4c89c50c06a6159d15f66eb5ab41ce669a1bd4")
                .unwrap(),
            Felt252::from_hex("0x29927c8af6bccf3f6fda035981e765a7bdbf18a2dc0d630494f8758aa908e2b")
                .unwrap(),
            &[Felt252::from_hex(
                    "0x7794e240544f56f345118c67c4c89c50c06a6159d15f66eb5ab41ce669a1bd4",
                )
                .unwrap(),
                Felt252::from_hex("0x0").unwrap()],
            StarknetChainId::TestNet.to_felt(),
        );

        assert_eq!(
            tx_hash,
            Felt252::from_hex("0x77a5b45a5ade8d59914b1a764f0a5d1e916e398b4089caed6fecd147b20e35")
                .unwrap()
        )
    }
}
