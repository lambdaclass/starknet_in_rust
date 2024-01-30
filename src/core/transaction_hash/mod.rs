use crate::core::errors::hash_errors::HashError;
use crate::transaction::{DataAvailabilityMode, ResourceBounds};
use crate::{
    core::contract_address::compute_deprecated_class_hash,
    definitions::constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR, hash_utils::compute_hash_on_elements,
    services::api::contract_classes::deprecated_contract_class::ContractClass, utils::Address,
};
use cairo_vm::Felt252;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::{Num, ToBytes, Zero};
use starknet_crypto::FieldElement;

#[derive(Debug)]
/// Enum representing the different types of transaction hash prefixes.
pub enum TransactionHashPrefix {
    Declare,
    Deploy,
    DeployAccount,
    Invoke,
    L1Handler,
}

// Returns the associated prefix value for a given transaction type.
impl TransactionHashPrefix {
    fn get_prefix(&self) -> Felt252 {
        match self {
            TransactionHashPrefix::Declare => Felt252::from_dec_str("28258975365558885").unwrap(),
            TransactionHashPrefix::Deploy => Felt252::from_dec_str("110386840629113").unwrap(),
            TransactionHashPrefix::DeployAccount => {
                Felt252::from_dec_str("2036277798190617858034555652763252").unwrap()
            }
            TransactionHashPrefix::Invoke => Felt252::from_dec_str("115923154332517").unwrap(),
            TransactionHashPrefix::L1Handler => {
                Felt252::from_dec_str("510926345461491391292786").unwrap()
            }
        }
    }
}

/// Calculates the transaction hash in the StarkNet network - a unique identifier of the
/// transaction.
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
pub fn calculate_transaction_hash_common_poseidon(
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
    lazy_static! {
        // DataAvalability::L1 as felt << DataAvailability bits: 0 << 32
        static ref DA_MODE_L1_SHL_DA_MODE_BITS: FieldElement =
            FieldElement::ZERO;
        // DataAvalability::L2 as felt << DataAvailability bits: 1 << 32
        static ref DA_MODE_L2_SHL_DA_MODE_BITS: FieldElement = (1_u32 << DATA_AVAILABILITY_MODE_BITS).into();
    };
    let fee_fields_hash = hash_fee_related_fields(tip, &l1_resource_bounds, &l2_resource_bounds);

    // Its easier to match to constants than to use the Into<Felt252> implementation and handle bitshifts using BigUint
    let da_mode_concatenation = match nonce_data_availability_mode {
        DataAvailabilityMode::L1 => *DA_MODE_L1_SHL_DA_MODE_BITS,
        DataAvailabilityMode::L2 => *DA_MODE_L2_SHL_DA_MODE_BITS,
    } + match fee_data_availability_mode {
        DataAvailabilityMode::L1 => FieldElement::ZERO,
        DataAvailabilityMode::L2 => FieldElement::ONE,
    };

    let field_element = |f: Felt252| {
        // Conversion between two felt types shouldn't fail
        FieldElement::from_bytes_be(&f.to_bytes_be()).unwrap_or_default()
    };

    let mut data_to_hash: Vec<FieldElement> = vec![
        field_element(tx_hash_prefix.get_prefix()),
        field_element(version),
        field_element(sender_address.0),
        fee_fields_hash,
        starknet_crypto::poseidon_hash_many(&paymaster_data.iter().map(|f| field_element(*f)).collect::<Vec<_>>()),
        field_element(chain_id),
        field_element(nonce),
        da_mode_concatenation,
    ];
    data_to_hash.extend_from_slice(&tx_type_specific_data.iter().map(|f| field_element(*f)).collect::<Vec<_>>());
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

// TODO[0.13] Investigate how transaction hashes are calculated for V3 Txs (aka without max_fee)
/// Calculates the transaction hash in the StarkNet network - a unique identifier of the
/// transaction.
/// The transaction hash is a hash chain of the following information:
///    1. A prefix that depends on the transaction type.
///    2. The transaction's version.
///    3. Contract address.
///    4. Entry point selector.
///    5. A hash chain of the calldata.
///    6. The transaction's maximum fee.
///    7. The network's chain ID.
/// Each hash chain computation begins with 0 as initialization and ends with its length appended.
/// The length is appended in order to avoid collisions of the following kind:
/// ```txt
///     H([x,y,z]) = h(h(x,y),z) = H([w, z]) where w = h(x,y)
/// ```
#[allow(clippy::too_many_arguments)]
pub fn calculate_transaction_hash_common(
    tx_hash_prefix: TransactionHashPrefix,
    version: Felt252,
    contract_address: &Address,
    entry_point_selector: Felt252,
    calldata: &[Felt252],
    max_fee: u128,
    chain_id: Felt252,
    additional_data: &[Felt252],
) -> Result<Felt252, HashError> {
    let calldata_hash = compute_hash_on_elements(calldata)?;

    let mut data_to_hash: Vec<Felt252> = vec![
        tx_hash_prefix.get_prefix(),
        version,
        contract_address.0,
        entry_point_selector,
        calldata_hash,
        max_fee.into(),
        chain_id,
    ];

    data_to_hash.extend(additional_data.iter().cloned());

    compute_hash_on_elements(&data_to_hash)
}

/// Calculate the hash for deploying a transaction.
pub fn calculate_deploy_transaction_hash(
    version: Felt252,
    contract_address: &Address,
    constructor_calldata: &[Felt252],
    chain_id: Felt252,
) -> Result<Felt252, HashError> {
    calculate_transaction_hash_common(
        TransactionHashPrefix::Deploy,
        version,
        contract_address,
        *CONSTRUCTOR_ENTRY_POINT_SELECTOR,
        constructor_calldata,
        0, // Considered 0 for Deploy transaction hash calculation purposes.
        chain_id,
        &[],
    )
}

// TODO[0.13] Investigate how transaction hashes are calculated for V3 Txs (aka without max_fee)
/// Calculate the hash for deploying an account transaction.
#[allow(clippy::too_many_arguments)]
pub fn calculate_deploy_account_transaction_hash(
    version: Felt252,
    contract_address: &Address,
    class_hash: Felt252,
    constructor_calldata: &[Felt252],
    max_fee: u128,
    nonce: Felt252,
    salt: Felt252,
    chain_id: Felt252,
) -> Result<Felt252, HashError> {
    let mut calldata: Vec<Felt252> = vec![class_hash, salt];
    calldata.extend_from_slice(constructor_calldata);

    calculate_transaction_hash_common(
        TransactionHashPrefix::DeployAccount,
        version,
        contract_address,
        Felt252::ZERO,
        &calldata,
        max_fee,
        chain_id,
        &[nonce],
    )
}

/// Calculate the hash for a declared transaction.
pub fn calculate_declare_transaction_hash(
    contract_class: &ContractClass,
    chain_id: Felt252,
    sender_address: &Address,
    max_fee: u128,
    version: Felt252,
    nonce: Felt252,
) -> Result<Felt252, HashError> {
    let class_hash = compute_deprecated_class_hash(contract_class)
        .map_err(|e| HashError::FailedToComputeHash(e.to_string()))?;

    let (calldata, additional_data) = if !version.is_zero() {
        (vec![class_hash], vec![nonce])
    } else {
        (Vec::new(), vec![class_hash])
    };

    calculate_transaction_hash_common(
        TransactionHashPrefix::Declare,
        version,
        sender_address,
        Felt252::ZERO,
        &calldata,
        max_fee,
        chain_id,
        &additional_data,
    )
}

// ----------------------------
//      V2 Hash Functions
// ----------------------------

// TODO[0.13] Investigate how transaction hashes are calculated for V3 Txs (aka without max_fee)
pub fn calculate_declare_v2_transaction_hash(
    sierra_class_hash: Felt252,
    compiled_class_hash: Felt252,
    chain_id: Felt252,
    sender_address: &Address,
    max_fee: u128,
    version: Felt252,
    nonce: Felt252,
) -> Result<Felt252, HashError> {
    let calldata = [sierra_class_hash].to_vec();
    let additional_data = [nonce, compiled_class_hash].to_vec();

    calculate_transaction_hash_common(
        TransactionHashPrefix::Declare,
        version,
        sender_address,
        Felt252::ZERO,
        &calldata,
        max_fee,
        chain_id,
        &additional_data,
    )
}

#[cfg(test)]
mod tests {
    use cairo_vm::Felt252;
    use coverage_helper::test;

    use crate::definitions::block_context::StarknetChainId;

    use super::*;

    #[test]
    fn calculate_transaction_hash_common_test() {
        let tx_hash_prefix = TransactionHashPrefix::Declare;
        let version = 0.into();
        let contract_address = Address(42.into());
        let entry_point_selector = 100.into();
        let calldata = vec![540.into(), 338.into()];
        let max_fee = 10;
        let chain_id = 1.into();
        let additional_data: Vec<Felt252> = Vec::new();

        // Expected value taken from Python implementation of calculate_transaction_hash_common function
        let expected = Felt252::from_dec_str(
            "2401716064129505935860131145275652294383308751137512921151718435935971973354",
        )
        .unwrap();

        let result = calculate_transaction_hash_common(
            tx_hash_prefix,
            version,
            &contract_address,
            entry_point_selector,
            &calldata,
            max_fee,
            chain_id,
            &additional_data,
        )
        .unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn calculate_declare_hash_test() {
        let chain_id = StarknetChainId::MainNet;
        let sender_address = Address(
            Felt252::from_dec_str(
                "78963962122521774108119849325604561253807220406669671815499681746608877924",
            )
            .unwrap(),
        );
        let max_fee = 30580718124600;
        let version = 1.into();
        let nonce = 3746.into();
        let class_hash = Felt252::from_dec_str(
            "1935775813346111469198021973672033051732472907985289186515250543849860001197",
        )
        .unwrap();

        let (calldata, additional_data) = (vec![class_hash], vec![nonce]);

        let tx = calculate_transaction_hash_common(
            TransactionHashPrefix::Declare,
            version,
            &sender_address,
            Felt252::ZERO,
            &calldata,
            max_fee,
            chain_id.to_felt(),
            &additional_data,
        )
        .unwrap();

        assert_eq!(
            tx,
            Felt252::from_dec_str(
                "446404108171603570739811156347043235876209711235222547918688109133687877504"
            )
            .unwrap()
        )
    }
}
