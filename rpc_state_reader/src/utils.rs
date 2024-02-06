use std::{
    collections::HashMap,
    io::{self, Read},
};

use cairo_lang_starknet::contract_class::ContractEntryPoints;
use cairo_lang_utils::bigint::BigUintAsHex;
use serde::Deserialize;
use starknet::core::types::{LegacyContractEntryPoint, LegacyEntryPointsByType};
use starknet_api::{
    core::EntryPointSelector,
    deprecated_contract_class::{EntryPoint, EntryPointOffset, EntryPointType},
    hash::{StarkFelt, StarkHash},
    transaction::{DeclareTransaction, DeployAccountTransaction, InvokeTransaction, Transaction},
};

#[derive(Debug, Deserialize)]
pub struct MiddleSierraContractClass {
    pub sierra_program: Vec<BigUintAsHex>,
    pub contract_class_version: String,
    pub entry_points_by_type: ContractEntryPoints,
}

pub fn map_entry_points_by_type_legacy(
    entry_points_by_type: LegacyEntryPointsByType,
) -> HashMap<EntryPointType, Vec<EntryPoint>> {
    let entry_types_to_points = HashMap::from([
        (
            EntryPointType::Constructor,
            entry_points_by_type.constructor,
        ),
        (EntryPointType::External, entry_points_by_type.external),
        (EntryPointType::L1Handler, entry_points_by_type.l1_handler),
    ]);

    let to_contract_entry_point = |entrypoint: &LegacyContractEntryPoint| -> EntryPoint {
        let felt: StarkFelt = StarkHash::new(entrypoint.selector.to_bytes_be()).unwrap();
        EntryPoint {
            offset: EntryPointOffset(entrypoint.offset as usize),
            selector: EntryPointSelector(felt),
        }
    };

    let mut entry_points_by_type_map = HashMap::new();
    for (entry_point_type, entry_points) in entry_types_to_points.into_iter() {
        let values = entry_points
            .iter()
            .map(to_contract_entry_point)
            .collect::<Vec<_>>();
        entry_points_by_type_map.insert(entry_point_type, values);
    }

    entry_points_by_type_map
}

/// Uncompresses a Gz Encoded vector of bytes and returns a string or error
/// Here &[u8] implements BufRead
pub fn decode_reader(bytes: Vec<u8>) -> io::Result<String> {
    use flate2::bufread;
    let mut gz = bufread::GzDecoder::new(&bytes[..]);
    let mut s = String::new();
    gz.read_to_string(&mut s)?;
    Ok(s)
}

/// Freestanding deserialize method to avoid a new type.
pub fn deserialize_transaction_json(
    transaction: serde_json::Value,
) -> serde_json::Result<Transaction> {
    let tx_type: String = serde_json::from_value(transaction["type"].clone())?;
    let tx_version: String = serde_json::from_value(transaction["version"].clone())?;

    match tx_type.as_str() {
        "INVOKE" => match tx_version.as_str() {
            "0x0" => Ok(Transaction::Invoke(InvokeTransaction::V0(
                serde_json::from_value(transaction)?,
            ))),
            "0x1" => Ok(Transaction::Invoke(InvokeTransaction::V1(
                serde_json::from_value(transaction)?,
            ))),
            "0x3" => Ok(Transaction::Invoke(InvokeTransaction::V3(
                serde_json::from_value(transaction)?,
            ))),
            x => Err(serde::de::Error::custom(format!(
                "unimplemented invoke version: {x}"
            ))),
        },
        "DEPLOY_ACCOUNT" => match tx_version.as_str() {
            "0x1" => Ok(Transaction::DeployAccount(DeployAccountTransaction::V1(
                serde_json::from_value(transaction)?,
            ))),
            "0x3" => Ok(Transaction::DeployAccount(DeployAccountTransaction::V3(
                serde_json::from_value(transaction)?,
            ))),
            x => Err(serde::de::Error::custom(format!(
                "unimplemented declare version: {x}"
            ))),
        },
        "DECLARE" => match tx_version.as_str() {
            "0x0" => Ok(Transaction::Declare(DeclareTransaction::V0(
                serde_json::from_value(transaction)?,
            ))),
            "0x1" => Ok(Transaction::Declare(DeclareTransaction::V1(
                serde_json::from_value(transaction)?,
            ))),
            "0x2" => Ok(Transaction::Declare(DeclareTransaction::V2(
                serde_json::from_value(transaction)?,
            ))),
            "0x3" => Ok(Transaction::Declare(DeclareTransaction::V3(
                serde_json::from_value(transaction)?,
            ))),
            x => Err(serde::de::Error::custom(format!(
                "unimplemented declare version: {x}"
            ))),
        },
        "L1_HANDLER" => Ok(Transaction::L1Handler(serde_json::from_value(transaction)?)),
        x => Err(serde::de::Error::custom(format!(
            "unimplemented transaction type deserialization: {x}"
        ))),
    }
}
