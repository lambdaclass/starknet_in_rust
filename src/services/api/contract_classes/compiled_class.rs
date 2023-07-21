use std::collections::HashMap;
use std::io::{self, Read};

use crate::core::contract_address::{compute_hinted_class_hash, CairoProgramToHash};
use crate::services::api::contract_classes::deprecated_contract_class::AbiType;
use crate::{EntryPointType, ContractEntryPoint};
use crate::services::api::contract_class_errors::ContractClassError;

use super::deprecated_contract_class::ContractClass;
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
use cairo_vm::felt::Felt252;
use cairo_vm::types::program::Program;
use serde::{Serialize, Deserialize};
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

                let program = Program::from_bytes(&as_str.clone().as_bytes(), None).unwrap();

                // let hinted_class_hash = compute_hinted_class_hash();
                let mut entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>  = HashMap::new();

                let constructor_entries = _deprecated_contract_class.entry_points_by_type.clone().constructor.into_iter().map(|entrypoint| 
                    ContractEntryPoint::new(Felt252::from_bytes_be(&entrypoint.selector.to_bytes_be()), entrypoint.offset as usize)
                ).collect::<Vec<ContractEntryPoint>>();
                entry_points_by_type.insert(EntryPointType::Constructor, constructor_entries);

                let external_entries = _deprecated_contract_class.entry_points_by_type.clone().external.into_iter().map(|entrypoint| 
                    ContractEntryPoint::new(Felt252::from_bytes_be(&entrypoint.selector.to_bytes_be()), entrypoint.offset as usize)
                ).collect::<Vec<ContractEntryPoint>>();
                entry_points_by_type.insert(EntryPointType::External, external_entries);

                let l1_handler_entries = _deprecated_contract_class.entry_points_by_type.clone().l1_handler.into_iter().map(|entrypoint| 
                    ContractEntryPoint::new(Felt252::from_bytes_be(&entrypoint.selector.to_bytes_be()), entrypoint.offset as usize)
                ).collect::<Vec<ContractEntryPoint>>();
                entry_points_by_type.insert(EntryPointType::Constructor, l1_handler_entries);

                let v = serde_json::to_value(&_deprecated_contract_class.abi).unwrap();
                let abi: Option<AbiType> = serde_json::from_value(v).unwrap();

                let cairo_program_to_hash: CairoProgramToHash = serde_json::from_str(as_str.as_str()).unwrap();
                
                let serialized_cc = SerializedContractClass { 
                    program: cairo_program_to_hash,
                    entry_points_by_type: serde_json::to_value(&_deprecated_contract_class.entry_points_by_type).unwrap(),
                    abi: serde_json::to_value(&_deprecated_contract_class.abi).unwrap(),
                };

                let v = serde_json::to_value(&serialized_cc).unwrap();
                let hinted_class_hash = compute_hinted_class_hash(&v).unwrap();

                CompiledClass::Deprecated(Box::new(ContractClass {
                    program,
                    entry_points_by_type,
                    abi,
                    hinted_class_hash,
                }))
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SerializedContractClass<'a> {
    /// Main program definition.
    #[serde(borrow)]
    program: CairoProgramToHash<'a>,
    entry_points_by_type: serde_json::Value,
    abi: serde_json::Value,
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
