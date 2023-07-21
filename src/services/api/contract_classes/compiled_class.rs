use std::io::{self, Read};

use crate::services::api::contract_class_errors::ContractClassError;

use super::deprecated_contract_class::ContractClass;
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
use starknet::core::types::ContractClass as StarknetRsContractClass;
use starknet::core::types::ContractClass::{Sierra, Legacy};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CompiledClass {
    Deprecated(Box<ContractClass>),
    Casm(Box<CasmContractClass>),
}

impl TryInto<CasmContractClass> for CompiledClass {
    type Error = ContractClassError;
    fn try_into(self) -> Result<CasmContractClass, ContractClassError> {
        match self {
            CompiledClass::Casm(boxed) => Ok(*boxed),
            _ => Err(ContractClassError::NotACasmContractClass),
        }
    }
}

impl TryInto<ContractClass> for CompiledClass {
    type Error = ContractClassError;
    fn try_into(self) -> Result<ContractClass, ContractClassError> {
        match self {
            CompiledClass::Deprecated(boxed) => Ok(*boxed),
            _ => Err(ContractClassError::NotADeprecatedContractClass),
        }
    }
}

extern crate serde;
extern crate serde_json;
// use std::str::FromStr;
// use serde::{de, Deserialize, Deserializer};

/// Represents a contract in the Starknet network.
// #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// pub struct SierraV2ContractClass {
//     pub sierra_program: Vec<BigUintAsHex>,
//     pub sierra_program_debug_info: Option<cairo_lang_sierra::debug_info::DebugInfo>,
//     pub contract_class_version: String,
//     pub entry_points_by_type: ContractEntryPoints,
//     #[serde(deserialize_with = "de_from_str")]
//     pub abi: Option<Contract>,
// }
// fn de_from_str<'de, D>(deserializer: D) -> Result<Contract, D::Error>
//     where D: Deserializer<'de>
// {
//     let s = String::deserialize(deserializer)?;
//     Contract::from_str(&s).map_err(de::Error::custom)
// }

// use starknet::core::serde::byte_array::base64;

/// Deprecated contract class.
///
/// The definition of a legacy (cairo 0) Starknet contract class.
// #[derive(Debug, Clone, Serialize, Deserialize)]
// #[cfg_attr(feature = "no_unknown_fields", serde(deny_unknown_fields))]
// pub struct CompressedLegacyContractClass {
//     /// A base64 representation of the compressed program code
//     #[serde(with = "base64")]
//     pub program: Vec<u8>,
//     /// Deprecated entry points by type
//     pub entry_points_by_type: LegacyEntryPointsByType,
//     /// Contract abi
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub abi: Option<Vec<LegacyContractAbiEntry>>,
// }


impl From<StarknetRsContractClass> for CompiledClass {
    fn from(starknet_rs_contract_class: StarknetRsContractClass) -> Self {
        match starknet_rs_contract_class {
            Sierra(flattened_sierra_contract_class) => {
                let v = serde_json::to_value(&flattened_sierra_contract_class).unwrap();
                let _sierra_cc: SierraContractClass = serde_json::from_value(v).unwrap();
                todo!()
            },
            Legacy(_deprecated_contract_class) => {
                // THIS WORKES!!!
                let as_str = decode_reader(_deprecated_contract_class.program).unwrap();
                println!("as_str: {}", as_str);
                todo!()
            },
        }
    }
}

use flate2::bufread;
// Uncompresses a Gz Encoded vector of bytes and returns a string or error
// Here &[u8] implements BufRead
fn decode_reader(bytes: Vec<u8>) -> io::Result<String> {
    let mut gz = bufread::GzDecoder::new(&bytes[..]);
    let mut s = String::new();
    gz.read_to_string(&mut s)?;
    Ok(s)
}
