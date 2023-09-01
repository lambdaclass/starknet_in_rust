use blockifier::execution::contract_class::{
    ContractClass as BlockifierContractClass, ContractClassV0, ContractClassV0Inner,
};
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_starknet::contract_class::{
    ContractClass as SierraContractClass, ContractEntryPoints,
};
use cairo_vm::types::program::Program;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use core::fmt;
use dotenv::dotenv;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use starknet::core::types::ContractClass as SNContractClass;
use starknet_api::block::{BlockNumber, BlockTimestamp};
use starknet_api::core::{ChainId, ClassHash, EntryPointSelector};
use starknet_api::deprecated_contract_class::EntryPointOffset;
use starknet_api::hash::StarkFelt;
use starknet_api::transaction::{InvokeTransaction, Transaction as SNTransaction, TransactionHash};
use starknet_api::{core::ContractAddress, hash::StarkHash, state::StorageKey};
use std::collections::HashMap;
use std::env;
use std::fmt::Display;
use std::sync::Arc;
use thiserror::Error;

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
}

/// Represents the tag of a block value.
#[derive(Copy, Clone)]
pub enum BlockTag {
    Latest,
    Pending,
}

impl Display for BlockTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            BlockTag::Latest => "latest",
            BlockTag::Pending => "pending",
        };
        write!(f, "{}", string)
    }
}

/// [`BlockValue`] is an Enum that represent which block we are going to use to retrieve information.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum BlockValue {
    /// String one of: ["latest", "pending"]
    Tag(BlockTag),
    /// Integer
    Number(BlockNumber),
    /// String with format: 0x{felt252}
    Hash(StarkHash),
}

impl From<BlockTag> for BlockValue {
    fn from(value: BlockTag) -> Self {
        BlockValue::Tag(value)
    }
}

impl From<BlockNumber> for BlockValue {
    fn from(value: BlockNumber) -> Self {
        BlockValue::Number(value)
    }
}

impl From<StarkHash> for BlockValue {
    fn from(value: StarkHash) -> Self {
        BlockValue::Hash(value)
    }
}

impl BlockValue {
    fn to_value(self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(match self {
            BlockValue::Tag(block_tag) => block_tag.to_string().into(),
            BlockValue::Number(block_number) => json!({ "block_number": block_number }),
            BlockValue::Hash(block_hash) => json!({ "block_hash": block_hash }),
        })
    }
}

pub struct RpcBlockInfo {
    /// The sequence number of the last block created.
    pub block_number: BlockNumber,
    /// Timestamp of the beginning of the last block creation attempt.
    pub block_timestamp: BlockTimestamp,
    /// The sequencer address of this block.
    pub sequencer_address: ContractAddress,
    /// The transactions of this block.
    pub transactions: Vec<SNTransaction>,
}

#[derive(Deserialize)]
pub struct RpcResponse<T> {
    result: T,
}

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

    fn rpc_call_result<T: for<'a> Deserialize<'a>>(
        &self,
        params: &serde_json::Value,
    ) -> Result<T, RpcError> {
        Ok(self.rpc_call::<RpcResponse<T>>(params)?.result)
    }

    fn rpc_call<T: for<'a> Deserialize<'a>>(
        &self,
        params: &serde_json::Value,
    ) -> Result<T, RpcError> {
        #[cfg(test)]
        {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            use std::path::Path;

            let dir = Path::new("test-responses");
            let mut hasher = DefaultHasher::new();
            params.to_string().hash(&mut hasher);
            let hash = hasher.finish();
            let filename = format!("{}-{}.json", self.chain, hash);
            let file = dir.join(filename);

            if file.exists() {
                let res = std::fs::read_to_string(file).unwrap();
                serde_json::from_str(&res).map_err(|err| RpcError::RpcCall(err.to_string()))
            } else {
                let res: serde_json::Value = Self::deserialize_call(
                    self.rpc_call_no_deserialize(params)?.into_json().unwrap(),
                )?;
                std::fs::write(file, res.to_string()).unwrap();
                serde_json::from_value(res).map_err(|err| RpcError::RpcCall(err.to_string()))
            }
        }
        #[cfg(not(test))]
        {
            Self::deserialize_call(self.rpc_call_no_deserialize(params)?.into_json().unwrap())
        }
    }

    fn rpc_call_no_deserialize(
        &self,
        params: &serde_json::Value,
    ) -> Result<ureq::Response, RpcError> {
        ureq::post(&format!(
            "https://{}.infura.io/v3/{}",
            self.chain, self.api_key
        ))
        .set("Content-Type", "application/json")
        .set("accept", "application/json")
        .send_json(params)
        .map_err(|err| RpcError::Request(err.to_string()))
    }

    fn deserialize_call<T: for<'a> Deserialize<'a>>(
        response: serde_json::Value,
    ) -> Result<T, RpcError> {
        serde_json::from_value(response).map_err(|err| RpcError::RpcCall(err.to_string()))
    }
}

#[derive(Debug)]
pub struct TransactionTrace {
    pub validate_invocation: RpcCallInfo,
    pub function_invocation: RpcCallInfo,
    pub fee_transfer_invocation: RpcCallInfo,
    pub signature: Vec<StarkFelt>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct RpcExecutionResources {
    pub n_steps: usize,
    pub n_memory_holes: usize,
    pub builtin_instance_counter: HashMap<String, usize>,
}

#[derive(Debug)]
pub struct RpcCallInfo {
    pub execution_resources: VmExecutionResources,
    pub retdata: Option<Vec<StarkFelt>>,
    pub calldata: Option<Vec<StarkFelt>>,
    pub internal_calls: Vec<RpcCallInfo>,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct RpcTransactionReceipt {
    #[serde(deserialize_with = "actual_fee_deser")]
    actual_fee: u128,
    block_hash: StarkHash,
    block_number: u64,
    execution_status: String,
    #[serde(rename = "type")]
    tx_type: String,
}

fn actual_fee_deser<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    let hex: String = Deserialize::deserialize(deserializer)?;
    Ok(u128::from_str_radix(&hex[2..], 16).unwrap())
}

impl<'de> Deserialize<'de> for RpcCallInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;

        // Parse execution_resources
        let execution_resources_value = value["execution_resources"].clone();

        let execution_resources = VmExecutionResources {
            n_steps: serde_json::from_value(execution_resources_value["n_steps"].clone())
                .map_err(serde::de::Error::custom)?,
            n_memory_holes: serde_json::from_value(
                execution_resources_value["n_memory_holes"].clone(),
            )
            .map_err(serde::de::Error::custom)?,
            builtin_instance_counter: serde_json::from_value(
                execution_resources_value["builtin_instance_counter"].clone(),
            )
            .map_err(serde::de::Error::custom)?,
        };

        // Parse retdata
        let retdata_value = value["result"].clone();
        let retdata = serde_json::from_value(retdata_value).unwrap();

        // Parse calldata
        let calldata_value = value["calldata"].clone();
        let calldata = serde_json::from_value(calldata_value).unwrap();

        // Parse internal calls
        let internal_calls_value = value["internal_calls"].clone();
        let mut internal_calls = vec![];

        for call in internal_calls_value.as_array().unwrap() {
            internal_calls
                .push(serde_json::from_value(call.clone()).map_err(serde::de::Error::custom)?);
        }

        Ok(RpcCallInfo {
            execution_resources,
            retdata,
            calldata,
            internal_calls,
        })
    }
}

impl<'de> Deserialize<'de> for TransactionTrace {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;

        let validate_invocation = value["validate_invocation"].clone();
        let function_invocation = value["function_invocation"].clone();
        let fee_transfer_invocation = value["fee_transfer_invocation"].clone();
        let signature_value = value["signature"].clone();

        Ok(TransactionTrace {
            validate_invocation: serde_json::from_value(validate_invocation)
                .map_err(serde::de::Error::custom)?,
            function_invocation: serde_json::from_value(function_invocation)
                .map_err(serde::de::Error::custom)?,
            fee_transfer_invocation: serde_json::from_value(fee_transfer_invocation)
                .map_err(serde::de::Error::custom)?,
            signature: serde_json::from_value(signature_value).map_err(serde::de::Error::custom)?,
        })
    }
}

/// Freestanding deserialize method to avoid a new type.
fn deserialize_transaction_json(
    transaction: serde_json::Value,
) -> serde_json::Result<SNTransaction> {
    let tx_type: String = serde_json::from_value(transaction["type"].clone())?;
    let tx_version: String = serde_json::from_value(transaction["version"].clone())?;

    match tx_type.as_str() {
        "INVOKE" => match tx_version.as_str() {
            "0x0" => Ok(SNTransaction::Invoke(InvokeTransaction::V0(
                serde_json::from_value(transaction)?,
            ))),
            "0x1" => Ok(SNTransaction::Invoke(InvokeTransaction::V1(
                serde_json::from_value(transaction)?,
            ))),
            x => Err(serde::de::Error::custom(format!(
                "unimplemented invoke version: {x}"
            ))),
        },
        x => Err(serde::de::Error::custom(format!(
            "unimplemented transaction type deserialization: {x}"
        ))),
    }
}

impl RpcState {
    /// Requests the transaction trace to the Feeder Gateway API.
    /// It's useful for testing the transaction outputs like:
    /// - execution resources
    /// - actual fee
    /// - events
    /// - return data
    pub fn get_transaction_trace(&self, hash: &TransactionHash) -> TransactionTrace {
        let chain_name = self.get_chain_name();
        let response = ureq::get(&format!(
            "https://{}.starknet.io/feeder_gateway/get_transaction_trace",
            chain_name
        ))
        .query("transactionHash", &hash.0.to_string())
        .call()
        .unwrap();

        serde_json::from_str(&response.into_string().unwrap()).unwrap()
    }

    /// Requests the given transaction to the Feeder Gateway API.
    pub fn get_transaction(&self, hash: &TransactionHash) -> SNTransaction {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getTransactionByHash",
            "params": [hash.to_string()],
            "id": 1
        });
        let result = self.rpc_call::<serde_json::Value>(&params).unwrap()["result"].clone();

        deserialize_transaction_json(result).unwrap()
    }

    /// Gets the gas price of a given block.
    pub fn get_gas_price(&self, block_number: u64) -> serde_json::Result<u128> {
        let chain_name = self.get_chain_name();

        let response = ureq::get(&format!(
            "https://{}.starknet.io/feeder_gateway/get_block",
            chain_name
        ))
        .query("blockNumber", &block_number.to_string())
        .call()
        .unwrap();

        let res: serde_json::Value = response.into_json().expect("should be json");

        let gas_price_hex = res["gas_price"].as_str().unwrap();
        let gas_price = u128::from_str_radix(gas_price_hex.trim_start_matches("0x"), 16).unwrap();
        Ok(gas_price)
    }

    pub fn get_chain_name(&self) -> ChainId {
        ChainId(match self.chain {
            RpcChain::MainNet => "alpha-mainnet".to_string(),
            RpcChain::TestNet => "alpha4".to_string(),
            RpcChain::TestNet2 => "alpha4-2".to_string(),
        })
    }

    pub fn get_block_info(&self) -> RpcBlockInfo {
        let get_block_info_params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getBlockWithTxs",
            "params": [self.block.to_value().unwrap()],
            "id": 1
        });

        let block_info: serde_json::Value = self.rpc_call(&get_block_info_params).unwrap();
        let sequencer_address: StarkFelt =
            serde_json::from_value(block_info["result"]["sequencer_address"].clone()).unwrap();

        let transactions: Vec<_> = block_info["result"]["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|result| deserialize_transaction_json(result.clone()).ok())
            .collect();

        RpcBlockInfo {
            block_number: BlockNumber(
                block_info["result"]["block_number"]
                    .to_string()
                    .parse::<u64>()
                    .unwrap(),
            ),
            block_timestamp: BlockTimestamp(
                block_info["result"]["timestamp"]
                    .to_string()
                    .parse::<u64>()
                    .unwrap(),
            ),
            sequencer_address: ContractAddress(sequencer_address.try_into().unwrap()),
            transactions,
        }
    }

    pub fn get_contract_class(&self, class_hash: &ClassHash) -> SNContractClass {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getClass",
            "params": [self.block.to_value().unwrap(), class_hash.0.to_string()],
            "id": 1
        });

        self.rpc_call_result(&params).unwrap()
    }

    pub fn get_class_hash_at(&self, contract_address: &ContractAddress) -> ClassHash {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getClassHashAt",
            "params": [self.block.to_value().unwrap(), contract_address.0.key().clone().to_string()],
            "id": 1
        });

        let hash = self.rpc_call_result(&params).unwrap();

        ClassHash(hash)
    }

    pub fn get_nonce_at(&self, contract_address: &ContractAddress) -> StarkFelt {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getNonce",
            "params": [self.block.to_value().unwrap(), contract_address.0.key().clone().to_string()],
            "id": 1
        });

        self.rpc_call_result(&params).unwrap()
    }

    fn get_storage_at(&self, contract_address: &ContractAddress, key: &StorageKey) -> StarkFelt {
        let contract_address = contract_address.0.key();
        let key = key.0.key();
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getStorageAt",
            "params": [contract_address.to_string(),
            key.to_string(), self.block.to_value().unwrap()],
            "id": 1
        });

        self.rpc_call_result(&params).unwrap()
    }

    /// Requests the given transaction to the Feeder Gateway API.
    pub fn get_transaction_receipt(&self, hash: &TransactionHash) -> RpcTransactionReceipt {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getTransactionReceipt",
            "params": [hash.to_string()],
            "id": 1
        });
        self.rpc_call_result(&params).unwrap()
    }
}

mod utils {
    use std::io::{self, Read};

    use cairo_lang_utils::bigint::BigUintAsHex;
    use starknet::core::types::{LegacyContractEntryPoint, LegacyEntryPointsByType};
    use starknet_api::deprecated_contract_class::{EntryPoint, EntryPointType};

    use super::*;

    #[derive(Debug, Deserialize)]
    pub struct MiddleSierraContractClass {
        pub sierra_program: Vec<BigUintAsHex>,
        pub contract_class_version: String,
        pub entry_points_by_type: ContractEntryPoints,
    }

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

    // Uncompresses a Gz Encoded vector of bytes and returns a string or error
    // Here &[u8] implements BufRead
    pub(crate) fn decode_reader(bytes: Vec<u8>) -> io::Result<String> {
        use flate2::bufread;
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
        stark_felt,
    };
    use starknet_in_rust::transaction::InvokeFunction;

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
        let rpc_state = RpcState::new(RpcChain::MainNet, BlockTag::Latest.into());

        let class_hash =
            class_hash!("0298e56befa6d1446b86ed5b900a9ba51fd2faa683cd6f50e8f833c0fb847216");
        // This belongs to
        // https://starkscan.co/class/0x0298e56befa6d1446b86ed5b900a9ba51fd2faa683cd6f50e8f833c0fb847216
        // which is cairo1.0

        rpc_state.get_contract_class(&class_hash);
    }

    #[test]
    fn test_get_contract_class_cairo0() {
        let rpc_state = RpcState::new(RpcChain::MainNet, BlockTag::Latest.into());

        let class_hash =
            class_hash!("025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918");
        rpc_state.get_contract_class(&class_hash);
    }

    #[test]
    fn test_get_class_hash_at() {
        let rpc_state = RpcState::new(RpcChain::MainNet, BlockTag::Latest.into());
        let address =
            contract_address!("00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9");

        assert_eq!(
            rpc_state.get_class_hash_at(&address),
            class_hash!("025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918")
        );
    }

    #[test]
    fn test_get_nonce_at() {
        let rpc_state = RpcState::new(RpcChain::TestNet, BlockTag::Latest.into());
        // Contract deployed by xqft which will not be used again, so nonce changes will not break
        // this test.
        let address =
            contract_address!("07185f2a350edcc7ea072888edb4507247de23e710cbd56084c356d265626bea");
        assert_eq!(rpc_state.get_nonce_at(&address), stark_felt!("0x0"));
    }

    #[test]
    fn test_get_storage_at() {
        let rpc_state = RpcState::new(RpcChain::MainNet, BlockTag::Latest.into());
        let address =
            contract_address!("00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9");
        let key = StorageKey(patricia_key!(0u128));

        assert_eq!(rpc_state.get_storage_at(&address, &key), stark_felt!("0x0"));
    }

    #[test]
    fn test_get_transaction() {
        let rpc_state = RpcState::new(RpcChain::MainNet, BlockTag::Latest.into());
        let tx_hash = TransactionHash(stark_felt!(
            "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955"
        ));

        rpc_state.get_transaction(&tx_hash);
    }

    #[test]
    fn test_try_from_invoke() {
        let rpc_state = RpcState::new(RpcChain::MainNet, BlockTag::Latest.into());
        let tx_hash = TransactionHash(stark_felt!(
            "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955"
        ));

        let tx = rpc_state.get_transaction(&tx_hash);
        let parsed = match tx {
            SNTransaction::Invoke(y) => InvokeFunction::try_from(y),
            _ => unreachable!(),
        };

        assert!(parsed.is_ok());
    }

    #[test]
    fn test_get_block_info() {
        let rpc_state = RpcState::new(RpcChain::MainNet, BlockTag::Latest.into());

        rpc_state.get_block_info();
    }

    // Tested with the following query to the Feeder Gateway API:
    // https://alpha4-2.starknet.io/feeder_gateway/get_transaction_trace?transactionHash=0x019feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc
    #[test]
    fn test_get_transaction_trace() {
        let rpc_state = RpcState::new(RpcChain::TestNet2, BlockTag::Latest.into());

        let tx_hash = TransactionHash(stark_felt!(
            "19feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc"
        ));

        let tx_trace = rpc_state.get_transaction_trace(&tx_hash);

        assert_eq!(
            tx_trace.signature,
            vec![
                stark_felt!("ffab1c47d8d5e5b76bdcc4af79e98205716c36b440f20244c69599a91ace58"),
                stark_felt!("6aa48a0906c9c1f7381c1a040c043b649eeac1eea08f24a9d07813f6b1d05fe"),
            ]
        );

        assert_eq!(
            tx_trace.validate_invocation.calldata,
            Some(vec![
                stark_felt!("1"),
                stark_felt!("690c876e61beda61e994543af68038edac4e1cb1990ab06e52a2d27e56a1232"),
                stark_felt!("1f24f689ced5802b706d7a2e28743fe45c7bfa37431c97b1c766e9622b65573"),
                stark_felt!("0"),
                stark_felt!("9"),
                stark_felt!("9"),
                stark_felt!("4"),
                stark_felt!("4254432d55534443"),
                stark_felt!("f02e7324ecbd65ce267"),
                stark_felt!("5754492d55534443"),
                stark_felt!("8e13050d06d8f514c"),
                stark_felt!("4554482d55534443"),
                stark_felt!("f0e4a142c3551c149d"),
                stark_felt!("4a50592d55534443"),
                stark_felt!("38bd34c31a0a5c"),
            ])
        );
        assert_eq!(tx_trace.validate_invocation.retdata, Some(vec![]));
        assert_eq!(
            tx_trace.validate_invocation.execution_resources,
            VmExecutionResources {
                n_steps: 790,
                n_memory_holes: 51,
                builtin_instance_counter: HashMap::from([
                    ("range_check_builtin".to_string(), 20),
                    ("ecdsa_builtin".to_string(), 1),
                    ("pedersen_builtin".to_string(), 2),
                ]),
            }
        );
        assert_eq!(tx_trace.validate_invocation.internal_calls.len(), 1);

        assert_eq!(
            tx_trace.function_invocation.calldata,
            Some(vec![
                stark_felt!("1"),
                stark_felt!("690c876e61beda61e994543af68038edac4e1cb1990ab06e52a2d27e56a1232"),
                stark_felt!("1f24f689ced5802b706d7a2e28743fe45c7bfa37431c97b1c766e9622b65573"),
                stark_felt!("0"),
                stark_felt!("9"),
                stark_felt!("9"),
                stark_felt!("4"),
                stark_felt!("4254432d55534443"),
                stark_felt!("f02e7324ecbd65ce267"),
                stark_felt!("5754492d55534443"),
                stark_felt!("8e13050d06d8f514c"),
                stark_felt!("4554482d55534443"),
                stark_felt!("f0e4a142c3551c149d"),
                stark_felt!("4a50592d55534443"),
                stark_felt!("38bd34c31a0a5c"),
            ])
        );
        assert_eq!(
            tx_trace.function_invocation.retdata,
            Some(vec![0u128.into()])
        );
        assert_eq!(
            tx_trace.function_invocation.execution_resources,
            VmExecutionResources {
                n_steps: 2808,
                n_memory_holes: 136,
                builtin_instance_counter: HashMap::from([
                    ("range_check_builtin".to_string(), 49),
                    ("pedersen_builtin".to_string(), 14),
                ]),
            }
        );
        assert_eq!(tx_trace.function_invocation.internal_calls.len(), 1);
        assert_eq!(
            tx_trace.function_invocation.internal_calls[0]
                .internal_calls
                .len(),
            1
        );
        assert_eq!(
            tx_trace.function_invocation.internal_calls[0].internal_calls[0]
                .internal_calls
                .len(),
            7
        );

        assert_eq!(
            tx_trace.fee_transfer_invocation.calldata,
            Some(vec![
                stark_felt!("1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8"),
                stark_felt!("2b0322a23ba4"),
                stark_felt!("0"),
            ])
        );
        assert_eq!(
            tx_trace.fee_transfer_invocation.retdata,
            Some(vec![1u128.into()])
        );
        assert_eq!(
            tx_trace.fee_transfer_invocation.execution_resources,
            VmExecutionResources {
                n_steps: 586,
                n_memory_holes: 42,
                builtin_instance_counter: HashMap::from([
                    ("range_check_builtin".to_string(), 21),
                    ("pedersen_builtin".to_string(), 4),
                ]),
            }
        );
        assert_eq!(tx_trace.fee_transfer_invocation.internal_calls.len(), 1);
    }

    #[test]
    fn test_get_transaction_receipt() {
        let rpc_state = RpcState::new(RpcChain::MainNet, BlockTag::Latest.into());
        let tx_hash = TransactionHash(stark_felt!(
            "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955"
        ));

        rpc_state.get_transaction_receipt(&tx_hash);
    }
}

mod blockifier_transaction_tests {
    use blockifier::{
        block_context::BlockContext,
        execution::contract_class::ContractClass,
        state::{
            cached_state::{CachedState, GlobalContractCache},
            state_api::{StateReader, StateResult},
        },
        transaction::{
            account_transaction::AccountTransaction,
            objects::TransactionExecutionInfo,
            transactions::{ExecutableTransaction, InvokeTransaction},
        },
    };
    use starknet_api::{
        contract_address,
        core::{CompiledClassHash, Nonce, PatriciaKey},
        patricia_key, stark_felt,
        transaction::TransactionHash,
    };

    use super::*;

    pub struct RpcStateReader(RpcState);

    impl StateReader for RpcStateReader {
        fn get_storage_at(
            &mut self,
            contract_address: ContractAddress,
            key: StorageKey,
        ) -> StateResult<StarkFelt> {
            Ok(self.0.get_storage_at(&contract_address, &key))
        }

        fn get_nonce_at(&mut self, contract_address: ContractAddress) -> StateResult<Nonce> {
            Ok(Nonce(self.0.get_nonce_at(&contract_address)))
        }

        fn get_class_hash_at(
            &mut self,
            contract_address: ContractAddress,
        ) -> StateResult<ClassHash> {
            Ok(self.0.get_class_hash_at(&contract_address))
        }

        /// Returns the contract class of the given class hash.
        fn get_compiled_contract_class(
            &mut self,
            class_hash: &ClassHash,
        ) -> StateResult<ContractClass> {
            Ok(match self.0.get_contract_class(class_hash) {
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
            })
        }

        /// Returns the compiled class hash of the given class hash.
        fn get_compiled_class_hash(
            &mut self,
            class_hash: ClassHash,
        ) -> StateResult<CompiledClassHash> {
            Ok(CompiledClassHash(
                self.0
                    .get_class_hash_at(&ContractAddress(class_hash.0.try_into().unwrap()))
                    .0,
            ))
        }
    }

    #[allow(unused)]
    pub fn execute_tx(
        tx_hash: &str,
        network: RpcChain,
        block_number: BlockNumber,
    ) -> (
        TransactionExecutionInfo,
        TransactionTrace,
        RpcTransactionReceipt,
    ) {
        let tx_hash = tx_hash.strip_prefix("0x").unwrap();

        // Instantiate the RPC StateReader and the CachedState
        let rpc_reader = RpcStateReader(RpcState::new(network, block_number.into()));
        let gas_price = rpc_reader.0.get_gas_price(block_number.0).unwrap();

        // Get values for block context before giving ownership of the reader
        let chain_id = rpc_reader.0.get_chain_name();
        let RpcBlockInfo {
            block_number,
            block_timestamp,
            sequencer_address,
            ..
        } = rpc_reader.0.get_block_info();

        // Get transaction before giving ownership of the reader
        let tx_hash = TransactionHash(stark_felt!(tx_hash));
        let sn_api_tx = rpc_reader.0.get_transaction(&tx_hash);

        let trace = rpc_reader.0.get_transaction_trace(&tx_hash);
        let receipt = rpc_reader.0.get_transaction_receipt(&tx_hash);

        // Create state from RPC reader
        let global_cache = GlobalContractCache::default();
        let mut state = CachedState::new(rpc_reader, global_cache);

        let fee_token_address =
            contract_address!("049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7");

        const N_STEPS_FEE_WEIGHT: f64 = 0.01;
        let vm_resource_fee_cost = Arc::new(HashMap::from([
            ("n_steps".to_string(), N_STEPS_FEE_WEIGHT),
            ("output_builtin".to_string(), 0.0),
            ("pedersen_builtin".to_string(), N_STEPS_FEE_WEIGHT * 32.0),
            ("range_check_builtin".to_string(), N_STEPS_FEE_WEIGHT * 16.0),
            ("ecdsa_builtin".to_string(), N_STEPS_FEE_WEIGHT * 2048.0),
            ("bitwise_builtin".to_string(), N_STEPS_FEE_WEIGHT * 64.0),
            ("ec_op_builtin".to_string(), N_STEPS_FEE_WEIGHT * 1024.0),
            ("poseidon_builtin".to_string(), N_STEPS_FEE_WEIGHT * 32.0),
            (
                "segment_arena_builtin".to_string(),
                N_STEPS_FEE_WEIGHT * 10.0,
            ),
            ("keccak_builtin".to_string(), N_STEPS_FEE_WEIGHT * 2048.0), // 2**11
        ]));

        let block_context = BlockContext {
            chain_id,
            block_number,
            block_timestamp,
            sequencer_address,
            fee_token_address,
            vm_resource_fee_cost,
            gas_price,
            invoke_tx_max_n_steps: 1_000_000,
            validate_max_n_steps: 1_000_000,
            max_recursion_depth: 500,
        };

        // Map starknet_api transaction to blockifier's
        let blockifier_tx = match sn_api_tx {
            SNTransaction::Invoke(tx) => {
                let invoke = InvokeTransaction { tx, tx_hash };
                AccountTransaction::Invoke(invoke)
            }
            _ => unimplemented!(),
        };

        (
            blockifier_tx
                .execute(&mut state, &block_context, true, true)
                .unwrap(),
            trace,
            receipt,
        )
    }

    #[cfg(test)]
    mod test {
        use blockifier::execution::entry_point::CallInfo;
        use pretty_assertions::assert_eq;
        use test_case::test_case;

        use super::*;

        #[test]
        fn test_get_gas_price() {
            let block = BlockValue::Number(BlockNumber(169928));
            let rpc_state = RpcState::new(RpcChain::MainNet, block);

            let price = rpc_state.get_gas_price(169928).unwrap();
            assert_eq!(price, 22804578690);
        }

        #[test]
        fn test_recent_tx() {
            let (tx_info, trace, receipt) = execute_tx(
                "0x05d200ef175ba15d676a68b36f7a7b72c17c17604eda4c1efc2ed5e4973e2c91",
                RpcChain::MainNet,
                BlockNumber(169928),
            );

            let TransactionExecutionInfo {
                execute_call_info,
                actual_fee,
                ..
            } = tx_info;

            let CallInfo {
                vm_resources,
                inner_calls,
                ..
            } = execute_call_info.unwrap();

            assert_eq!(vm_resources, trace.function_invocation.execution_resources);
            assert_eq!(
                inner_calls.len(),
                trace.function_invocation.internal_calls.len()
            );

            assert_eq!(actual_fee.0, receipt.actual_fee);
        }

        #[test_case(
            "0x05d200ef175ba15d676a68b36f7a7b72c17c17604eda4c1efc2ed5e4973e2c91",
            169928, // real block 169929
            RpcChain::MainNet
        )]
        #[test_case(
            "0x0528ec457cf8757f3eefdf3f0728ed09feeecc50fd97b1e4c5da94e27e9aa1d6",
            169928, // real block 169929
            RpcChain::MainNet
        )]
        #[test_case(
            "0x0737677385a30ec4cbf9f6d23e74479926975b74db3d55dc5e46f4f8efee41cf",
            169928, // real block 169929
            RpcChain::MainNet
        )]
        #[test_case(
            "0x026c17728b9cd08a061b1f17f08034eb70df58c1a96421e73ee6738ad258a94c",
            169928, // real block 169929
            RpcChain::MainNet
        )]
        #[test_case(
            // fails: review later
            "0x0743092843086fa6d7f4a296a226ee23766b8acf16728aef7195ce5414dc4d84",
            186548, // real block     186549
            RpcChain::MainNet
            => ignore["review later"]
        )]
        #[test_case(
            // fails: review later
            "0x00724fc4a84f489ed032ebccebfc9541eb8dc64b0e76b933ed6fc30cd6000bd1",
            186551, // real block     186552
            RpcChain::MainNet
            => ignore["review later"]
        )]
        fn test_case_tx(hash: &str, block_number: u64, chain: RpcChain) {
            let (tx_info, trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number));

            let TransactionExecutionInfo {
                execute_call_info,
                actual_fee,
                ..
            } = tx_info;

            let CallInfo {
                vm_resources,
                inner_calls,
                ..
            } = execute_call_info.unwrap();

            assert_eq!(
                vm_resources, trace.function_invocation.execution_resources,
                "execution resources mismatch"
            );
            assert_eq!(
                inner_calls.len(),
                trace.function_invocation.internal_calls.len(),
                "internal calls length mismatch"
            );

            assert_eq!(actual_fee.0, receipt.actual_fee, "actual_fee mismatch");
        }
    }
}

mod starknet_in_rust_transaction_tests {
    use cairo_vm::felt::{felt_str, Felt252};
    use starknet_api::{core::PatriciaKey, stark_felt, transaction::TransactionHash};
    use starknet_in_rust::{
        core::errors::state_errors::StateError,
        definitions::{
            block_context::{BlockContext, StarknetChainId, StarknetOsConfig},
            constants::{
                DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS,
                DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
                DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT, DEFAULT_INVOKE_TX_MAX_N_STEPS,
                DEFAULT_VALIDATE_MAX_N_STEPS,
            },
        },
        execution::TransactionExecutionInfo,
        services::api::contract_classes::compiled_class::CompiledClass,
        state::{
            cached_state::{CachedState, ContractClassCache},
            state_api::StateReader,
            state_cache::StorageEntry,
            BlockInfo,
        },
        transaction::{InvokeFunction, Transaction},
        utils::{Address, ClassHash},
    };

    use super::*;

    pub struct RpcStateReader(RpcState);

    impl StateReader for RpcStateReader {
        fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
            let hash = ClassHash(StarkHash::new(*class_hash).unwrap());
            Ok(CompiledClass::from(self.0.get_contract_class(&hash)))
        }

        fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError> {
            let address = ContractAddress(
                PatriciaKey::try_from(
                    StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
                )
                .unwrap(),
            );
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(self.0.get_class_hash_at(&address).0.bytes());
            Ok(bytes)
        }

        fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError> {
            let address = ContractAddress(
                PatriciaKey::try_from(
                    StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
                )
                .unwrap(),
            );
            let nonce = self.0.get_nonce_at(&address);
            Ok(Felt252::from_bytes_be(nonce.bytes()))
        }
        fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
            let (contract_address, key) = storage_entry;
            let address = ContractAddress(
                PatriciaKey::try_from(
                    StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
                )
                .unwrap(),
            );
            let key = StorageKey(PatriciaKey::try_from(StarkHash::new(*key).unwrap()).unwrap());
            let value = self.0.get_storage_at(&address, &key);
            Ok(Felt252::from_bytes_be(value.bytes()))
        }
        fn get_compiled_class_hash(&self, class_hash: &ClassHash) -> Result<[u8; 32], StateError> {
            let address = ContractAddress(
                PatriciaKey::try_from(StarkHash::new(*class_hash).unwrap()).unwrap(),
            );
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(self.0.get_class_hash_at(&address).0.bytes());
            Ok(bytes)
        }
    }

    #[allow(unused)]
    pub fn execute_tx(
        tx_hash: &str,
        network: RpcChain,
        block_number: BlockNumber,
    ) -> (
        TransactionExecutionInfo,
        TransactionTrace,
        RpcTransactionReceipt,
    ) {
        let fee_token_address = Address(felt_str!(
            "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
            16
        ));

        let tx_hash = tx_hash.strip_prefix("0x").unwrap();

        // Instantiate the RPC StateReader and the CachedState
        let rpc_reader = RpcStateReader(RpcState::new(network, block_number.into()));
        let gas_price = rpc_reader.0.get_gas_price(block_number.0).unwrap();

        // Get values for block context before giving ownership of the reader
        let chain_id = match rpc_reader.0.chain {
            RpcChain::MainNet => StarknetChainId::MainNet,
            RpcChain::TestNet => StarknetChainId::TestNet,
            RpcChain::TestNet2 => StarknetChainId::TestNet2,
        };
        let starknet_os_config =
            StarknetOsConfig::new(chain_id.to_felt(), fee_token_address, gas_price);
        let block_info = {
            let RpcBlockInfo {
                block_number,
                block_timestamp,
                sequencer_address,
                ..
            } = rpc_reader.0.get_block_info();

            let block_number = block_number.0;
            let block_timestamp = block_timestamp.0;
            let sequencer_address =
                Address(Felt252::from_bytes_be(sequencer_address.0.key().bytes()));

            BlockInfo {
                block_number,
                block_timestamp,
                gas_price,
                sequencer_address,
            }
        };

        // Get transaction before giving ownership of the reader
        let tx_hash = TransactionHash(stark_felt!(tx_hash));
        let tx = match rpc_reader.0.get_transaction(&tx_hash) {
            SNTransaction::Invoke(tx) => {
                Transaction::InvokeFunction(InvokeFunction::try_from(tx).unwrap())
            }
            _ => unimplemented!(),
        };

        let trace = rpc_reader.0.get_transaction_trace(&tx_hash);
        let receipt = rpc_reader.0.get_transaction_receipt(&tx_hash);

        let class_cache = ContractClassCache::default();
        let mut state = CachedState::new(Arc::new(rpc_reader), class_cache);

        let block_context = BlockContext::new(
            starknet_os_config,
            DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
            DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT,
            DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS.clone(),
            DEFAULT_INVOKE_TX_MAX_N_STEPS,
            DEFAULT_VALIDATE_MAX_N_STEPS,
            block_info,
            Default::default(),
            true,
        );

        (
            tx.execute(&mut state, &block_context, u128::MAX).unwrap(),
            trace,
            receipt,
        )
    }

    #[cfg(test)]
    mod test {
        use pretty_assertions::assert_eq;
        use starknet_in_rust::execution::CallInfo;
        use test_case::test_case;

        use super::*;

        #[test]
        fn test_get_gas_price() {
            let block = BlockValue::Number(BlockNumber(169928));
            let rpc_state = RpcState::new(RpcChain::MainNet, block);

            let price = rpc_state.get_gas_price(169928).unwrap();
            assert_eq!(price, 22804578690);
        }

        #[test_case(
            "0x05d200ef175ba15d676a68b36f7a7b72c17c17604eda4c1efc2ed5e4973e2c91",
            169928, // real block 169929
            RpcChain::MainNet
        )]
        #[test_case(
            "0x0528ec457cf8757f3eefdf3f0728ed09feeecc50fd97b1e4c5da94e27e9aa1d6",
            169928, // real block 169929
            RpcChain::MainNet
        )]
        #[test_case(
            "0x0737677385a30ec4cbf9f6d23e74479926975b74db3d55dc5e46f4f8efee41cf",
            169928, // real block 169929
            RpcChain::MainNet
        )]
        #[test_case(
            "0x026c17728b9cd08a061b1f17f08034eb70df58c1a96421e73ee6738ad258a94c",
            169928, // real block 169929
            RpcChain::MainNet
        )]
        #[test_case(
            // review later
            "0x0743092843086fa6d7f4a296a226ee23766b8acf16728aef7195ce5414dc4d84",
            186548, // real block     186549
            RpcChain::MainNet
        )]
        #[test_case(
            // fails in blockifier too
            "0x00724fc4a84f489ed032ebccebfc9541eb8dc64b0e76b933ed6fc30cd6000bd1",
            186551, // real block     186552
            RpcChain::MainNet
        )]
        fn test_case_tx(hash: &str, block_number: u64, chain: RpcChain) {
            let (tx_info, trace, receipt) = execute_tx(hash, chain, BlockNumber(block_number));

            let TransactionExecutionInfo {
                call_info,
                actual_fee,
                ..
            } = tx_info;

            let CallInfo {
                execution_resources,
                internal_calls,
                ..
            } = call_info.unwrap();

            assert_eq!(
                execution_resources, trace.function_invocation.execution_resources,
                "execution resources mismatch"
            );
            assert_eq!(
                internal_calls.len(),
                trace.function_invocation.internal_calls.len(),
                "internal calls length mismatch"
            );

            assert_eq!(actual_fee, receipt.actual_fee, "actual_fee mismatch");
        }
    }
}
