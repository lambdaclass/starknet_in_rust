use blockifier::execution::contract_class::{
    ContractClass as BlockifierContractClass, ContractClassV0, ContractClassV0Inner,
    ContractClassV1, ContractClassV1Inner,
};
use cairo_lang_starknet::abi::Contract;
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::{
    ContractClass as SierraContractClass, ContractEntryPoints,
};
use cairo_vm::felt::{felt_str, Felt252};
use cairo_vm::types::program::Program;
use core::fmt;
use dotenv::dotenv;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use serde_with::{serde_as, DeserializeAs};
use starknet::core::types::{ContractClass as SNContractClass, FieldElement};
use starknet_api::core::EntryPointSelector;
use starknet_api::deprecated_contract_class::{self, EntryPointOffset};
use starknet_api::hash::StarkFelt;
use starknet_api::{core::ContractAddress, hash::StarkHash, state::StorageKey};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use thiserror::Error;

//#[derive(Debug, Clone, Deserialize)]
//#[serde(tag = "contract_class_version")]
//pub enum ContractClass {
//    #[serde(rename = "0.0.0")]
//    Deprecated(blockifier::execution::contract_class::ContractClassV0),
//    #[serde(rename = "0.1.0")]
//    Compiled(starknet_api::state::ContractClass),
//}

/// Starknet chains supported in Infura.
#[derive(Debug, Clone, Copy)]
pub enum RpcChain {
    MainNet,
    TestNet,
    TestNet2,
}

impl fmt::Display for RpcChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcChain::MainNet => write!(f, "starknet-mainnet"),
            RpcChain::TestNet => write!(f, "starknet-goerli"),
            RpcChain::TestNet2 => write!(f, "starknet-goerli2"),
        }
    }
}

/// A [StateReader] that holds all the data in memory.
///
/// This implementation is uses HTTP requests to call the RPC endpoint,
/// using Infura.
/// In order to use it an Infura API key is necessary.
pub struct RpcState {
    /// Enum with one of the supported Infura chains/
    chain: RpcChain,
    /// Infura API key.
    api_key: String,
    /// Struct that holds information on the block where we are going to use to read the state.
    block: BlockValue,
}

#[derive(Debug, Error)]
enum RpcError {
    #[error("RPC call failed with error: {0}")]
    RpcCall(String),
    #[error("Request failed with error: {0}")]
    Request(String),
    #[error("Failed to cast from: {0} to: {1} with error: {2}")]
    Cast(String, String, String),
}

/// [`BlockValue`] is an Enum that represent which block we are going to use to retrieve information.
#[allow(dead_code)]
pub enum BlockValue {
    /// String one of: ["latest", "pending"]
    Tag(serde_json::Value),
    /// Integer
    Number(serde_json::Value),
    /// String with format: 0x{felt252}
    Hash(serde_json::Value),
}

impl BlockValue {
    fn to_value(&self) -> serde_json::Value {
        match self {
            BlockValue::Tag(block_tag) => block_tag.clone(),
            BlockValue::Number(block_number) => json!({ "block_number": block_number }),
            BlockValue::Hash(block_hash) => json!({ "block_hash": block_hash }),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponseContractClass {
    result: SNContractClass,
}

// We use this new struct to cast the string that contains a [`Felt252`] in hex to a [`Felt252`]
struct FeltHex;

impl<'de> DeserializeAs<'de, Felt252> for FeltHex {
    fn deserialize_as<D>(deserializer: D) -> Result<Felt252, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.starts_with("0x") {
            true => Ok(Felt252::parse_bytes(value[2..].as_bytes(), 16).unwrap()),
            false => Ok(Felt252::parse_bytes(value.as_bytes(), 16).unwrap()),
        }
    }
}

#[serde_as]
#[derive(Debug, Deserialize)]
struct RpcResponseFelt252 {
    #[serde_as(as = "FeltHex")]
    result: Felt252,
}

pub struct RpcBlockInfo {
    /// The sequence number of the last block created.
    pub block_number: u64,
    /// Timestamp of the beginning of the last block creation attempt.
    pub block_timestamp: u64,
    /// The sequencer address of this block.
    pub sequencer_address: ContractAddress,
}

type RpcResponse = ureq::Response;

impl RpcState {
    pub fn new(chain: RpcChain, block: BlockValue) -> Self {
        if env::var("INFURA_API_KEY").is_err() {
            dotenv().expect("Missing .env file");
        }
        Self {
            chain,
            api_key: env::var("INFURA_API_KEY")
                .expect("Missing API Key in environment: INFURA_API_KEY"),
            block,
        }
    }

    fn rpc_call<T: for<'a> Deserialize<'a>>(
        &self,
        params: &serde_json::Value,
    ) -> Result<T, RpcError> {
        Self::deserialize_call(self.rpc_call_no_deserialize(params)?)
    }

    fn rpc_call_no_deserialize(&self, params: &serde_json::Value) -> Result<RpcResponse, RpcError> {
        ureq::post(&format!(
            "https://{}.infura.io/v3/{}",
            self.chain, self.api_key
        ))
        .set("Content-Type", "application/json")
        .set("accept", "application/json")
        .send_json(params)
        .map_err(|err| RpcError::Request(err.to_string()))
    }

    fn deserialize_call<T: for<'a> Deserialize<'a>>(response: RpcResponse) -> Result<T, RpcError> {
        let response = response.into_string().map_err(|err| {
            RpcError::Cast("Response".to_owned(), "String".to_owned(), err.to_string())
        })?;
        serde_json::from_str(&response).map_err(|err| RpcError::RpcCall(err.to_string()))
    }
}

// #[derive(Debug)]
// pub struct TransactionTrace {
//     pub validate_invocation: CallInfo,
//     pub function_invocation: CallInfo,
//     pub fee_transfer_invocation: CallInfo,
//     pub signature: Vec<Felt252>,
// }

// impl<'de> Deserialize<'de> for TransactionTrace {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let value: serde_json::Value = Deserialize::deserialize(deserializer)?;

//         let validate_invocation = value["validate_invocation"].clone();
//         let function_invocation = value["function_invocation"].clone();
//         let fee_transfer_invocation = value["fee_transfer_invocation"].clone();
//         let signature_value = value["signature"].clone();
//         // let signature = parse_felt_array(signature_value.as_array().unwrap());
//         let signature = vec![];

//         Ok(TransactionTrace {
//             validate_invocation: serde_json::from_value(validate_invocation)
//                 .map_err(serde::de::Error::custom)?,
//             function_invocation: serde_json::from_value(function_invocation)
//                 .map_err(serde::de::Error::custom)?,
//             fee_transfer_invocation: serde_json::from_value(fee_transfer_invocation)
//                 .map_err(serde::de::Error::custom)?,
//             signature,
//         })
//     }
// }

#[cfg(test)]
impl RpcState {
    /// Requests the transaction trace to the Feeder Gateway API.
    /// It's useful for testing the transaction outputs like:
    /// - execution resources
    /// - actual fee
    /// - events
    /// - return data
    // pub fn get_transaction_trace(&self, hash: Felt252) -> TransactionTrace {
    //     let chain_name = self.get_chain_name();
    //     let response = ureq::get(&format!(
    //         "https://{}.starknet.io/feeder_gateway/get_transaction_trace",
    //         chain_name
    //     ))
    //     .query("transactionHash", &format!("0x{}", hash.to_str_radix(16)))
    //     .call()
    //     .unwrap();

    //     serde_json::from_str(&response.into_string().unwrap()).unwrap()
    // }

    /// Requests the given transaction to the Feeder Gateway API.
    pub fn get_transaction(&self, hash: &str) -> starknet_api::transaction::Transaction {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getTransactionByHash",
            "params": [format!("0x{}", hash)],
            "id": 1
        });
        let response: serde_json::Value = self.rpc_call(&params).unwrap();
        let it: starknet_api::transaction::InvokeTransactionV1 =
            serde_json::from_value(response["result"].clone()).unwrap();
        let sn_api_invoke: starknet_api::transaction::InvokeTransaction =
            starknet_api::transaction::InvokeTransaction::V1(it);
        starknet_api::transaction::Transaction::Invoke(sn_api_invoke)
    }

    fn get_chain_name(&self) -> String {
        match self.chain {
            RpcChain::MainNet => "alpha-mainnet".to_string(),
            RpcChain::TestNet => "alpha4".to_string(),
            RpcChain::TestNet2 => "alpha4-2".to_string(),
        }
    }

    pub fn get_block_info(&self) -> RpcBlockInfo {
        let get_block_info_params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getBlockWithTxHashes",
            "params": [self.block.to_value()],
            "id": 1
        });

        let block_info: serde_json::Value = self.rpc_call(&get_block_info_params).unwrap();
        let sequencer_address =
            felt_str!(block_info["result"]["sequencer_address"].to_string()).to_be_bytes();

        RpcBlockInfo {
            block_number: block_info["result"]["block_number"]
                .to_string()
                .parse::<u64>()
                .unwrap(),
            block_timestamp: block_info["result"]["timestamp"]
                .to_string()
                .parse::<u64>()
                .unwrap(),
            sequencer_address: ContractAddress::try_from(
                StarkHash::new(sequencer_address).unwrap(),
            )
            .unwrap(),
        }
    }

    pub fn get_contract_class(
        &self,
        class_hash: &starknet_api::core::ClassHash,
    ) -> BlockifierContractClass {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getClass",
            "params": [self.block.to_value(), class_hash.0.to_string()],
            "id": 1
        });

        let response = self
            .rpc_call::<RpcResponseContractClass>(&params)
            .unwrap()
            .result;

        match response {
            SNContractClass::Legacy(compressed_legacy_cc) => {
                let as_str = utils::decode_reader(compressed_legacy_cc.program).unwrap();
                let program = Program::from_bytes(as_str.as_bytes(), None).unwrap();
                let entry_points_by_type = utils::map_entry_points_by_type_legacy(
                    compressed_legacy_cc.entry_points_by_type,
                );
                let inner = Arc::new(ContractClassV0Inner {
                    program,
                    entry_points_by_type,
                });
                BlockifierContractClass::V0(ContractClassV0(inner))
            }
            SNContractClass::Sierra(flattened_sierra_cc) => {
                let middle_sierra: utils::MiddleSierraContractClass = {
                    let v = serde_json::to_value(flattened_sierra_cc).unwrap();
                    serde_json::from_value(v).unwrap()
                };
                let sierra_cc = SierraContractClass {
                    sierra_program: middle_sierra.sierra_program,
                    contract_class_version: middle_sierra.contract_class_version,
                    entry_points_by_type: middle_sierra.entry_points_by_type,
                    sierra_program_debug_info: None,
                    abi: None,
                };
                let casm_cc = CasmContractClass::from_contract_class(sierra_cc, false).unwrap();
                BlockifierContractClass::V1(casm_cc.try_into().unwrap())
            }
        }
    }

    pub fn get_class_hash_at(
        &self,
        contract_address: &starknet_api::core::ContractAddress,
    ) -> starknet_api::core::ClassHash {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getClassHashAt",
            "params": [self.block.to_value(), contract_address.0.key().clone().to_string()],
            "id": 1
        });

        let response: starknet_api::core::ClassHash = self.rpc_call(&params).unwrap();

        response
    }

    pub fn get_nonce_at(&self, contract_address: &ContractAddress) -> Felt252 {
        let contract_address = Felt252::from_bytes_be(contract_address.0.key().bytes());
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getNonce",
            "params": [self.block.to_value(), format!("0x{}", contract_address.to_str_radix(16))],
            "id": 1
        });

        let resp: RpcResponseFelt252 = self.rpc_call(&params).unwrap();

        resp.result
    }

    fn get_storage_at(&self, contract_address: &ContractAddress, key: &StorageKey) -> Felt252 {
        let contract_address = Felt252::from_bytes_be(contract_address.0.key().bytes());
        let key = Felt252::from_bytes_be(key.0.key().bytes());
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getStorageAt",
            "params": [format!("0x{}", contract_address.to_str_radix(16)), format!(
                "0x{}",
                key.to_str_radix(16)
            ), self.block.to_value()],
            "id": 1
        });

        let resp: RpcResponseFelt252 = self.rpc_call(&params).unwrap();

        resp.result
    }
}

mod utils {
    use std::io::{self, Read};

    use cairo_lang_utils::bigint::BigUintAsHex;
    use starknet::core::types::{
        EntryPointsByType, LegacyContractEntryPoint, LegacyEntryPointsByType, SierraEntryPoint,
    };

    use super::*;

    #[derive(Debug, Deserialize)]
    pub struct MiddleSierraContractClass {
        pub sierra_program: Vec<BigUintAsHex>,
        pub contract_class_version: String,
        pub entry_points_by_type: ContractEntryPoints,
    }

    // FIXME: change type to use
    type EntryPointType = starknet_api::deprecated_contract_class::EntryPointType;
    type EntryPoint = starknet_api::deprecated_contract_class::EntryPoint;

    pub(crate) fn map_entry_points_by_type_legacy(
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

    use flate2::bufread;
    // Uncompresses a Gz Encoded vector of bytes and returns a string or error
    // Here &[u8] implements BufRead
    pub(crate) fn decode_reader(bytes: Vec<u8>) -> io::Result<String> {
        let mut gz = bufread::GzDecoder::new(&bytes[..]);
        let mut s = String::new();
        gz.read_to_string(&mut s)?;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use starknet_api::{
        core::{ClassHash, PatriciaKey},
        hash::StarkFelt,
        serde_utils::bytes_from_hex_str,
    };

    use super::*;

    /// A utility macro to create a [`PatriciaKey`] from a hex string / unsigned integer representation.
    /// Imported from starknet_api
    macro_rules! patricia_key {
        ($s:expr) => {
            PatriciaKey::try_from(StarkHash::try_from($s).unwrap()).unwrap()
        };
    }

    /// A utility macro to create a [`ClassHash`] from a hex string / unsigned integer representation.
    /// Imported from starknet_api
    macro_rules! class_hash {
        ($s:expr) => {
            ClassHash(StarkHash::try_from($s).unwrap())
        };
    }

    /// A utility macro to create a [`ContractAddress`] from a hex string / unsigned integer
    /// representation.
    /// Imported from starknet_api
    macro_rules! contract_address {
        ($s:expr) => {
            ContractAddress(patricia_key!($s))
        };
    }

    #[test]
    fn test_get_contract_class_cairo1() {
        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );

        let class_hash =
            class_hash!("0298e56befa6d1446b86ed5b900a9ba51fd2faa683cd6f50e8f833c0fb847216");
        // This belongs to
        // https://starkscan.co/class/0x0298e56befa6d1446b86ed5b900a9ba51fd2faa683cd6f50e8f833c0fb847216
        // which is cairo1.0

        rpc_state.get_contract_class(&class_hash);
    }

    #[test]
    fn test_get_contract_class_cairo0() {
        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );

        let class_hash =
            class_hash!("025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918");
        rpc_state.get_contract_class(&class_hash);
    }

    #[test]
    fn test_get_class_hash_at() {
        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );
        let address =
            contract_address!("00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9");

        assert_eq!(
            rpc_state.get_class_hash_at(&address),
            class_hash!("025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918")
        );
    }

    #[test]
    fn test_get_nonce_at() {
        let rpc_state = RpcState::new(
            RpcChain::TestNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );
        // Contract deployed by xqft which will not be used again, so nonce changes will not break
        // this test.
        let address =
            contract_address!("07185f2a350edcc7ea072888edb4507247de23e710cbd56084c356d265626bea");
        assert_eq!(rpc_state.get_nonce_at(&address), felt_str!("0", 16));
    }

    #[test]
    fn test_get_storage_at() {
        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );
        let address =
            contract_address!("00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9");
        let key = StorageKey(patricia_key!(0u128));

        assert_eq!(rpc_state.get_storage_at(&address, &key), felt_str!("0", 16));
    }

    #[test]
    fn test_get_transaction() {
        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );
        let tx_hash = "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955";

        rpc_state.get_transaction(tx_hash);
    }

    // #[test]
    // fn test_get_block_info() {
    //     let rpc_state = RpcState::new(
    //         RpcChain::MainNet,
    //         BlockValue::Tag(serde_json::to_value("latest").unwrap()),
    //     );

    //     let gas_price_str = "13563643256";
    //     let gas_price_u128 = gas_price_str.parse::<u128>().unwrap();

    //     let fee_token_address = Address(felt_str!(
    //         "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
    //         16
    //     ));

    //     let get_block_info_params = ureq::json!({
    //         "jsonrpc": "2.0",
    //         "method": "starknet_getBlockWithTxHashes",
    //         "params": [rpc_state.block.to_value()],
    //         "id": 1
    //     });
    //     let network: StarknetChainId = rpc_state.chain.into();
    //     let starknet_os_config =
    //         starknet_in_rust::definitions::block_context::StarknetOsConfig::new(
    //             network.to_felt(),
    //             fee_token_address.clone(),
    //             gas_price_u128,
    //         );
    //     let block_info: serde_json::Value = rpc_state.rpc_call(&get_block_info_params).unwrap();

    //     let block_info = starknet_in_rust::state::BlockInfo {
    //         block_number: block_info["result"]["block_number"]
    //             .to_string()
    //             .parse::<u64>()
    //             .unwrap(),
    //         block_timestamp: block_info["result"]["timestamp"]
    //             .to_string()
    //             .parse::<u64>()
    //             .unwrap(),
    //         gas_price: gas_price_u128 as u64,
    //         sequencer_address: fee_token_address,
    //     };

    //     assert_eq!(rpc_state.get_block_info(starknet_os_config,), block_info);
    // }

    // Tested with the following query to the Feeder Gateway API:
    // https://alpha4-2.starknet.io/feeder_gateway/get_transaction_trace?transactionHash=0x019feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc
    // #[test]
    // fn test_get_transaction_trace() {
    //     let state_reader = RpcState::new(
    //         RpcChain::TestNet2,
    //         BlockValue::Number(serde_json::to_value(838683).unwrap()),
    //     );

    //     let tx_hash_str = "19feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc";
    //     let tx_hash = felt_str!(format!("{}", tx_hash_str), 16);

    //     let tx_trace = state_reader.get_transaction_trace(tx_hash);

    //     assert_eq!(
    //         tx_trace.signature,
    //         vec![
    //             felt_str!(
    //                 "ffab1c47d8d5e5b76bdcc4af79e98205716c36b440f20244c69599a91ace58",
    //                 16
    //             ),
    //             felt_str!(
    //                 "6aa48a0906c9c1f7381c1a040c043b649eeac1eea08f24a9d07813f6b1d05fe",
    //                 16
    //             ),
    //         ]
    //     );

    //     assert_eq!(
    //         tx_trace.validate_invocation.calldata,
    //         vec![
    //             felt_str!("1", 16),
    //             felt_str!(
    //                 "690c876e61beda61e994543af68038edac4e1cb1990ab06e52a2d27e56a1232",
    //                 16
    //             ),
    //             felt_str!(
    //                 "1f24f689ced5802b706d7a2e28743fe45c7bfa37431c97b1c766e9622b65573",
    //                 16
    //             ),
    //             felt_str!("0", 16),
    //             felt_str!("9", 16),
    //             felt_str!("9", 16),
    //             felt_str!("4", 16),
    //             felt_str!("4254432d55534443", 16),
    //             felt_str!("f02e7324ecbd65ce267", 16),
    //             felt_str!("5754492d55534443", 16),
    //             felt_str!("8e13050d06d8f514c", 16),
    //             felt_str!("4554482d55534443", 16),
    //             felt_str!("f0e4a142c3551c149d", 16),
    //             felt_str!("4a50592d55534443", 16),
    //             felt_str!("38bd34c31a0a5c", 16),
    //         ]
    //     );
    //     assert_eq!(tx_trace.validate_invocation.retdata, vec![]);
    //     assert_eq!(
    //         tx_trace.validate_invocation.execution_resources,
    //         ExecutionResources {
    //             n_steps: 790,
    //             n_memory_holes: 51,
    //             builtin_instance_counter: HashMap::from([
    //                 ("range_check_builtin".to_string(), 20),
    //                 ("ecdsa_builtin".to_string(), 1),
    //                 ("pedersen_builtin".to_string(), 2),
    //             ]),
    //         }
    //     );
    //     assert_eq!(tx_trace.validate_invocation.internal_calls.len(), 1);

    //     assert_eq!(
    //         tx_trace.function_invocation.calldata,
    //         vec![
    //             felt_str!("1", 16),
    //             felt_str!(
    //                 "690c876e61beda61e994543af68038edac4e1cb1990ab06e52a2d27e56a1232",
    //                 16
    //             ),
    //             felt_str!(
    //                 "1f24f689ced5802b706d7a2e28743fe45c7bfa37431c97b1c766e9622b65573",
    //                 16
    //             ),
    //             felt_str!("0", 16),
    //             felt_str!("9", 16),
    //             felt_str!("9", 16),
    //             felt_str!("4", 16),
    //             felt_str!("4254432d55534443", 16),
    //             felt_str!("f02e7324ecbd65ce267", 16),
    //             felt_str!("5754492d55534443", 16),
    //             felt_str!("8e13050d06d8f514c", 16),
    //             felt_str!("4554482d55534443", 16),
    //             felt_str!("f0e4a142c3551c149d", 16),
    //             felt_str!("4a50592d55534443", 16),
    //             felt_str!("38bd34c31a0a5c", 16),
    //         ]
    //     );
    //     assert_eq!(tx_trace.function_invocation.retdata, vec![0.into()]);
    //     assert_eq!(
    //         tx_trace.function_invocation.execution_resources,
    //         ExecutionResources {
    //             n_steps: 2808,
    //             n_memory_holes: 136,
    //             builtin_instance_counter: HashMap::from([
    //                 ("range_check_builtin".to_string(), 49),
    //                 ("pedersen_builtin".to_string(), 14),
    //             ]),
    //         }
    //     );
    //     assert_eq!(tx_trace.function_invocation.internal_calls.len(), 1);
    //     assert_eq!(
    //         tx_trace.function_invocation.internal_calls[0]
    //             .internal_calls
    //             .len(),
    //         1
    //     );
    //     assert_eq!(
    //         tx_trace.function_invocation.internal_calls[0].internal_calls[0]
    //             .internal_calls
    //             .len(),
    //         7
    //     );

    //     assert_eq!(
    //         tx_trace.fee_transfer_invocation.calldata,
    //         vec![
    //             felt_str!(
    //                 "1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
    //                 16
    //             ),
    //             felt_str!("2b0322a23ba4", 16),
    //             felt_str!("0", 16),
    //         ]
    //     );
    //     assert_eq!(tx_trace.fee_transfer_invocation.retdata, vec![1.into()]);
    //     assert_eq!(
    //         tx_trace.fee_transfer_invocation.execution_resources,
    //         ExecutionResources {
    //             n_steps: 586,
    //             n_memory_holes: 42,
    //             builtin_instance_counter: HashMap::from([
    //                 ("range_check_builtin".to_string(), 21),
    //                 ("pedersen_builtin".to_string(), 4),
    //             ]),
    //         }
    //     );
    //     assert_eq!(tx_trace.fee_transfer_invocation.internal_calls.len(), 1);
    // }
}
