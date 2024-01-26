use cairo_vm::vm::runners::{
    builtin_runner::{
        BITWISE_BUILTIN_NAME, EC_OP_BUILTIN_NAME, HASH_BUILTIN_NAME, KECCAK_BUILTIN_NAME,
        OUTPUT_BUILTIN_NAME, POSEIDON_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME,
        SIGNATURE_BUILTIN_NAME,
    },
    cairo_runner::ExecutionResources as VmExecutionResources,
};
use core::fmt;
use dotenv::dotenv;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use starknet::core::types::ContractClass as SNContractClass;
use starknet_api::{
    block::{BlockNumber, BlockTimestamp},
    core::{ChainId, ClassHash, ContractAddress},
    hash::{StarkFelt, StarkHash},
    state::StorageKey,
    transaction::{Transaction as SNTransaction, TransactionHash},
};
use starknet_in_rust::definitions::block_context::{GasPrices, StarknetChainId};
use std::{collections::HashMap, env, fmt::Display};

use crate::{rpc_state_errors::RpcStateError, utils};

/// Starknet chains supported in Infura.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum RpcChain {
    MainNet,
    TestNet,
    TestNet2,
}

impl From<RpcChain> for StarknetChainId {
    fn from(network: RpcChain) -> StarknetChainId {
        match network {
            RpcChain::MainNet => StarknetChainId::MainNet,
            RpcChain::TestNet => StarknetChainId::TestNet,
            RpcChain::TestNet2 => StarknetChainId::TestNet2,
        }
    }
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

impl From<RpcChain> for ChainId {
    fn from(value: RpcChain) -> Self {
        ChainId(match value {
            RpcChain::MainNet => "alpha-mainnet".to_string(),
            RpcChain::TestNet => "alpha4".to_string(),
            RpcChain::TestNet2 => "alpha4-2".to_string(),
        })
    }
}

/// A [StateReader] that holds all the data in memory.
///
/// This implementation is uses HTTP requests to call the RPC endpoint,
/// using Infura.
/// In order to use it an Infura API key is necessary.
#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct RpcState {
    /// Enum with one of the supported Infura chains/
    pub chain: RpcChain,
    /// RPC Endpoint URL.
    rpc_endpoint: String,
    /// Struct that holds information on the block where we are going to use to read the state.
    pub block: BlockValue,
}

/// Represents the tag of a block value.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
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
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
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

/// The RPC block info.
#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
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

/// A RPC response.
#[derive(Debug, Deserialize, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct RpcResponse<T> {
    result: T,
}

#[derive(Debug, Deserialize, Clone, Eq, PartialEq)]
pub struct TransactionTrace {
    pub validate_invocation: Option<RpcCallInfo>,
    #[serde(
        alias = "execute_invocation",
        alias = "constructor_invocation",
        alias = "function_invocation"
    )]
    pub execute_invocation: Option<RpcCallInfo>,
    pub fee_transfer_invocation: Option<RpcCallInfo>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct RpcExecutionResources {
    pub n_steps: usize,
    pub n_memory_holes: usize,
    pub builtin_instance_counter: HashMap<String, usize>,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct RpcCallInfo {
    pub retdata: Option<Vec<StarkFelt>>,
    pub calldata: Option<Vec<StarkFelt>>,
    pub internal_calls: Vec<RpcCallInfo>,
    pub revert_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RpcTransactionReceipt {
    pub actual_fee: FeePayment,
    pub block_hash: StarkHash,
    pub block_number: u64,
    pub execution_status: String,
    #[serde(rename = "type")]
    pub tx_type: String,
    #[serde(deserialize_with = "vm_execution_resources_deser")]
    pub execution_resources: VmExecutionResources,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
pub struct FeePayment {
    #[serde(deserialize_with = "fee_amount_deser")]
    pub amount: u128,
    pub unit: String,
}

fn fee_amount_deser<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    let hex: String = Deserialize::deserialize(deserializer)?;
    u128::from_str_radix(&hex[2..], 16).map_err(serde::de::Error::custom)
}

fn vm_execution_resources_deser<'de, D>(deserializer: D) -> Result<VmExecutionResources, D::Error>
where
    D: Deserializer<'de>,
{
    let value: serde_json::Value = Deserialize::deserialize(deserializer)?;
    // Parse n_steps
    let n_steps: usize = serde_json::from_value(
        value
            .get("steps")
            .ok_or(serde::de::Error::custom(
                RpcStateError::MissingRpcResponseField("steps".to_string()),
            ))?
            .clone(),
    )
    .map_err(|e| serde::de::Error::custom(e.to_string()))?;

    // Parse n_memory_holes
    let n_memory_holes: usize = if let Some(memory_holes) = value.get("memory_holes") {
        serde_json::from_value(memory_holes.clone())
            .map_err(|e| serde::de::Error::custom(e.to_string()))?
    } else {
        0
    };
    // Parse builtin instance counter
    const BUILTIN_NAMES: [&str; 8] = [
        OUTPUT_BUILTIN_NAME,
        RANGE_CHECK_BUILTIN_NAME,
        HASH_BUILTIN_NAME,
        SIGNATURE_BUILTIN_NAME,
        KECCAK_BUILTIN_NAME,
        BITWISE_BUILTIN_NAME,
        EC_OP_BUILTIN_NAME,
        POSEIDON_BUILTIN_NAME,
    ];
    let mut builtin_instance_counter = HashMap::new();
    for name in BUILTIN_NAMES {
        let builtin_counter: Option<usize> = value
            .get(format!("{}_applications", name))
            .and_then(|a| serde_json::from_value(a.clone()).ok());
        if let Some(builtin_counter) = builtin_counter {
            if builtin_counter > 0 {
                builtin_instance_counter.insert(name.to_string(), builtin_counter);
            }
        };
    }
    Ok(VmExecutionResources {
        n_steps,
        n_memory_holes,
        builtin_instance_counter,
    })
}

impl<'de> Deserialize<'de> for RpcCallInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value: serde_json::Value = Deserialize::deserialize(deserializer)?;

        // In case of a revert error, the struct will only contain the revert_reason field
        if let Some(revert_error) = value.get("revert_reason") {
            return Ok(RpcCallInfo {
                revert_reason: serde_json::from_value(revert_error.clone())
                    .map_err(|e| serde::de::Error::custom(e.to_string()))?,
                ..Default::default()
            });
        }
        // Parse retdata
        let retdata_value = value
            .get("result")
            .ok_or(serde::de::Error::custom(
                RpcStateError::MissingRpcResponseField("result".to_string()),
            ))?
            .clone();
        let retdata = serde_json::from_value(retdata_value)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;

        // Parse calldata
        let calldata_value = value
            .get("calldata")
            .ok_or(serde::de::Error::custom(
                RpcStateError::MissingRpcResponseField("calldata".to_string()),
            ))?
            .clone();
        let calldata = serde_json::from_value(calldata_value)
            .map_err(|e| serde::de::Error::custom(e.to_string()))?;

        // Parse internal calls
        let internal_calls_value = value
            .get("calls")
            .ok_or(serde::de::Error::custom(
                RpcStateError::MissingRpcResponseField("calls".to_string()),
            ))?
            .clone();
        let mut internal_calls = vec![];

        for call in internal_calls_value
            .as_array()
            .ok_or(serde::de::Error::custom(
                RpcStateError::RpcResponseWrongType("internal_calls".to_string()),
            ))?
        {
            internal_calls
                .push(serde_json::from_value(call.clone()).map_err(serde::de::Error::custom)?);
        }

        Ok(RpcCallInfo {
            retdata,
            calldata,
            internal_calls,
            revert_reason: None,
        })
    }
}

impl RpcState {
    pub fn new(chain: RpcChain, block: BlockValue, rpc_endpoint: &str) -> Self {
        Self {
            chain,
            rpc_endpoint: rpc_endpoint.to_string(),
            block,
        }
    }

    pub fn new_rpc(chain: RpcChain, block: BlockValue) -> Result<Self, RpcStateError> {
        if env::var("RPC_ENDPOINT_MAINNET").is_err() || env::var("RPC_ENDPOINT_TESTNET").is_err() {
            dotenv().map_err(|_| RpcStateError::MissingEnvFile)?;
        }

        let rpc_endpoint =
            match chain {
                RpcChain::MainNet => env::var("RPC_ENDPOINT_MAINNET")
                    .map_err(|_| RpcStateError::MissingRpcEndpoints)?,
                RpcChain::TestNet => env::var("RPC_ENDPOINT_TESTNET")
                    .map_err(|_| RpcStateError::MissingRpcEndpoints)?,
                RpcChain::TestNet2 => unimplemented!(),
            };

        Ok(Self::new(chain, block, &rpc_endpoint))
    }

    fn rpc_call_result<T: for<'a> Deserialize<'a>>(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<T, RpcStateError> {
        Ok(self.rpc_call::<RpcResponse<T>>(method, params)?.result)
    }

    fn rpc_call<T: for<'a> Deserialize<'a>>(
        &self,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<T, RpcStateError> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });
        let response = self.rpc_call_no_deserialize(&payload)?.into_json()?;
        Self::deserialize_call(response)
    }

    fn rpc_call_no_deserialize(
        &self,
        params: &serde_json::Value,
    ) -> Result<ureq::Response, RpcStateError> {
        ureq::post(&self.rpc_endpoint)
            .set("Content-Type", "application/json")
            .set("accept", "application/json")
            .send_json(params)
            .map_err(|err| {
                if err
                    .to_string()
                    .contains("request failed or timed out through")
                {
                    RpcStateError::RpcConnectionNotAvailable
                } else {
                    RpcStateError::Request(err.to_string())
                }
            })
    }

    fn deserialize_call<T: for<'a> Deserialize<'a>>(
        response: serde_json::Value,
    ) -> Result<T, RpcStateError> {
        serde_json::from_value(response).map_err(|err| RpcStateError::RpcCall(err.to_string()))
    }

    /// Requests the transaction trace to the Feeder Gateway API.
    /// It's useful for testing the transaction outputs like:
    /// - execution resources
    /// - actual fee
    /// - events
    /// - return data
    pub fn get_transaction_trace(
        &self,
        hash: &TransactionHash,
    ) -> Result<TransactionTrace, RpcStateError> {
        let result = self
            .rpc_call::<serde_json::Value>("starknet_traceTransaction", &json!([hash.to_string()]))?
            .get("result")
            .ok_or(RpcStateError::MissingRpcResponseField("result".into()))?
            .clone();
        serde_json::from_value(result).map_err(|e| RpcStateError::Request(e.to_string()))
    }

    /// Requests the given transaction to the Feeder Gateway API.
    pub fn get_transaction(&self, hash: &TransactionHash) -> Result<SNTransaction, RpcStateError> {
        let result = self
            .rpc_call::<serde_json::Value>(
                "starknet_getTransactionByHash",
                &json!([hash.to_string()]),
            )?
            .get("result")
            .ok_or(RpcStateError::MissingRpcResponseField("result".into()))?
            .clone();
        utils::deserialize_transaction_json(result).map_err(RpcStateError::SerdeJson)
    }

    /// Gets the gas price of a given block.
    pub fn get_gas_price(&self, block_number: u64) -> Result<GasPrices, RpcStateError> {
        let res = self
            .rpc_call::<serde_json::Value>(
                "starknet_getBlockWithTxHashes",
                &json!({"block_id" : { "block_number": block_number }}),
            )?
            .get("result")
            .ok_or(RpcStateError::MissingRpcResponseField("result".into()))?
            .clone();

        let gas_price_eth = u128::from_str_radix(
            res.get("l1_gas_price")
                .and_then(|gp| gp.get("price_in_wei"))
                .and_then(|gp| gp.as_str())
                .ok_or(RpcStateError::MissingRpcResponseField(
                    "gas_price.price_in_wei".to_string(),
                ))?
                .trim_start_matches("0x"),
            16,
        )
        .map_err(|_| RpcStateError::RpcResponseWrongType("gas_price".to_string()))?;

        let gas_price_strk = u128::from_str_radix(
            res.get("l1_gas_price")
                .and_then(|gp| gp.get("price_in_fri"))
                .and_then(|gp| gp.as_str())
                .ok_or(RpcStateError::MissingRpcResponseField(
                    "gas_price.price_in_fri".to_string(),
                ))?
                .trim_start_matches("0x"),
            16,
        )
        .map_err(|_| RpcStateError::RpcResponseWrongType("gas_price".to_string()))?;

        Ok(GasPrices::new(gas_price_eth, gas_price_strk))
    }

    pub fn get_chain_name(&self) -> ChainId {
        self.chain.into()
    }

    pub fn get_block_info(&self) -> Result<RpcBlockInfo, RpcStateError> {
        let block_info: serde_json::Value = self
            .rpc_call("starknet_getBlockWithTxs", &json!([self.block.to_value()?]))
            .map_err(|e| RpcStateError::RpcCall(e.to_string()))?;

        let sequencer_address: StarkFelt = block_info
            .get("result")
            .and_then(|result| result.get("sequencer_address"))
            .and_then(|sa| serde_json::from_value(sa.clone()).ok())
            .ok_or_else(|| {
                RpcStateError::RpcObjectHasNoField("block_info".into(), "sequencer_address".into())
            })?;

        let transactions: Vec<_> = block_info
            .get("result")
            .and_then(|result| result.get("transactions"))
            .and_then(|txs| txs.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|result| utils::deserialize_transaction_json(result.clone()).ok())
                    .collect()
            })
            .ok_or_else(|| {
                RpcStateError::RpcObjectHasNoField("block_info".into(), "transactions".into())
            })?;

        Ok(RpcBlockInfo {
            block_number: BlockNumber(
                block_info
                    .get("result")
                    .and_then(|result| result.get("block_number"))
                    .and_then(|v| v.to_string().parse::<u64>().ok())
                    .ok_or_else(|| {
                        RpcStateError::RpcObjectHasNoField(
                            "block_info".into(),
                            "block_number".into(),
                        )
                    })?,
            ),
            block_timestamp: BlockTimestamp(
                block_info
                    .get("result")
                    .and_then(|result| result.get("timestamp"))
                    .and_then(|v| v.to_string().parse::<u64>().ok())
                    .ok_or_else(|| {
                        RpcStateError::RpcObjectHasNoField("block_info".into(), "timestamp".into())
                    })?,
            ),
            sequencer_address: ContractAddress(
                sequencer_address
                    .try_into()
                    .map_err(|_| RpcStateError::StarkFeltToParticiaKeyConversion)?,
            ),
            transactions,
        })
    }

    pub fn get_contract_class(&self, class_hash: &ClassHash) -> Option<SNContractClass> {
        self.block.to_value().ok().and_then(|block| {
            self.rpc_call_result(
                "starknet_getClass",
                &json!([block, class_hash.0.to_string()]),
            )
            .ok()
        })
    }

    pub fn get_class_hash_at(&self, contract_address: &ContractAddress) -> ClassHash {
        let hash = self
            .block
            .to_value()
            .ok()
            .and_then(|block| {
                self.rpc_call_result(
                    "starknet_getClassHashAt",
                    &json!([block, contract_address.0.key().clone().to_string()]),
                )
                .ok()
            })
            .unwrap_or_default();

        ClassHash(hash)
    }

    pub fn get_nonce_at(&self, contract_address: &ContractAddress) -> StarkFelt {
        self.block
            .to_value()
            .ok()
            .and_then(|block| {
                self.rpc_call_result(
                    "starknet_getNonce",
                    &json!([block, contract_address.0.key().clone().to_string()]),
                )
                .ok()
            })
            // When running deploy_account transactions, the nonce doesn't exist on the previous block so we return 0
            .unwrap_or_default()
    }

    pub fn get_storage_at(
        &self,
        contract_address: &ContractAddress,
        key: &StorageKey,
    ) -> StarkFelt {
        let contract_address = contract_address.0.key();
        let key = key.0.key();
        self.block
            .to_value()
            .ok()
            .and_then(|block| {
                self.rpc_call_result(
                    "starknet_getStorageAt",
                    &json!([contract_address.to_string(), key.to_string(), block]),
                )
                .ok()
            })
            .unwrap_or_default()
    }

    /// Requests the given transaction to the Feeder Gateway API.
    pub fn get_transaction_receipt(
        &self,
        hash: &TransactionHash,
    ) -> Result<RpcTransactionReceipt, RpcStateError> {
        self.rpc_call_result("starknet_getTransactionReceipt", &json!([hash.to_string()]))
            .map_err(|e| RpcStateError::RpcCall(e.to_string()))
    }

    pub fn get_transaction_hashes(&self) -> Result<Vec<String>, RpcStateError> {
        let params = &json![vec![self.block.to_value()?]];
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getBlockWithTxHashes",
            "params": params,
            "id": 1
        });
        let response: serde_json::Value = self
            .rpc_call_no_deserialize(&payload)
            .unwrap()
            .into_json()?;
        let hashes: Vec<String> = response
            .get("result")
            .and_then(|res| res.get("transactions"))
            .and_then(|txs| txs.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|tx| tx.as_str().map(|x| x.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(hashes)
    }
}

#[test]
fn test_tx_hashes() {
    let rpc_state =
        RpcState::new_rpc(RpcChain::MainNet, BlockValue::Number(BlockNumber(397709))).unwrap();

    let hashes = rpc_state.get_transaction_hashes().unwrap();
    assert_eq!(hashes.len(), 211);
}
