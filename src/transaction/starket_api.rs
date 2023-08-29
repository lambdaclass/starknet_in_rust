use cairo_vm::felt::Felt252;
use num_traits::{One, Zero};

use crate::{definitions::constants::EXECUTE_ENTRY_POINT_SELECTOR, utils::Address};

use super::{DeployAccount, InvokeFunction};

fn convert_invoke_v0(value: starknet_api::transaction::InvokeTransactionV0) -> InvokeFunction {
    let contract_address = Address(Felt252::from_bytes_be(
        value.contract_address.0.key().bytes(),
    ));
    let max_fee = value.max_fee.0;
    let entry_point_selector = Felt252::from_bytes_be(value.entry_point_selector.0.bytes());
    let version = Felt252::zero();
    let nonce = None;
    let chain_id = Felt252::zero();

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
        version,
        calldata,
        signature,
        chain_id,
        nonce,
    )
    .unwrap()
}

fn convert_invoke_v1(value: starknet_api::transaction::InvokeTransactionV1) -> InvokeFunction {
    let contract_address = Address(Felt252::from_bytes_be(value.sender_address.0.key().bytes()));
    let max_fee = value.max_fee.0;
    let version = Felt252::one();
    let nonce = Felt252::from_bytes_be(value.nonce.0.bytes());
    let chain_id = Felt252::zero();
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
        version,
        calldata,
        signature,
        chain_id,
        Some(nonce),
    )
    .unwrap()
}

impl From<starknet_api::transaction::InvokeTransaction> for InvokeFunction {
    fn from(value: starknet_api::transaction::InvokeTransaction) -> Self {
        match value {
            starknet_api::transaction::InvokeTransaction::V0(v0) => convert_invoke_v0(v0),
            starknet_api::transaction::InvokeTransaction::V1(v1) => convert_invoke_v1(v1),
        }
    }
}

impl From<starknet_api::transaction::DeployAccountTransaction> for DeployAccount {
    fn from(value: starknet_api::transaction::DeployAccountTransaction) -> Self {
        let max_fee = value.max_fee.0;
        let version = Felt252::from_bytes_be(value.version.0.bytes());
        let nonce = Felt252::from_bytes_be(value.nonce.0.bytes());
        let class_hash: [u8; 32] = value.class_hash.0.bytes().try_into().unwrap();
        let contract_address_salt = Felt252::from_bytes_be(value.contract_address_salt.0.bytes());

        let signature = value
            .signature
            .0
            .iter()
            .map(|f| Felt252::from_bytes_be(f.bytes()))
            .collect();
        let constructor_calldata = value
            .constructor_calldata
            .0
            .as_ref()
            .iter()
            .map(|f| Felt252::from_bytes_be(f.bytes()))
            .collect();

        let chain_id = Felt252::zero();

        DeployAccount::new(
            class_hash,
            max_fee,
            version,
            nonce,
            constructor_calldata,
            signature,
            contract_address_salt,
            chain_id,
        )
        .unwrap()
    }
}
