use core::fmt;
use dotenv::dotenv;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use serde_with::{serde_as, DeserializeAs};
use starknet::core::types::ContractClass;
use starknet_in_rust::{
    core::errors::state_errors::StateError,
    execution::CallInfo,
    felt::Felt252,
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{state_api::StateReader, state_cache::StorageEntry},
    utils::{parse_felt_array, Address, ClassHash, CompiledClassHash},
};
use std::env;
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
struct RpcResponseProgram {
    result: ContractClass,
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
        let response = ureq::post(&format!(
            "https://{}.infura.io/v3/{}",
            self.chain, self.api_key
        ))
        .set("Content-Type", "application/json")
        .set("accept", "application/json")
        .send_json(params)
        .map_err(|err| RpcError::Request(err.to_string()))?
        .into_string()
        .map_err(|err| {
            RpcError::Cast("Response".to_owned(), "String".to_owned(), err.to_string())
        })?;
        serde_json::from_str(&response).map_err(|err| RpcError::RpcCall(err.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct TransactionTrace {
    pub validate_invocation: CallInfo,
    pub function_invocation: CallInfo,
    pub fee_transfer_invocation: CallInfo,
    pub signature: Vec<Felt252>,
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
        let signature = parse_felt_array(signature_value.as_array().unwrap());

        Ok(TransactionTrace {
            validate_invocation: serde_json::from_value(validate_invocation)
                .map_err(serde::de::Error::custom)?,
            function_invocation: serde_json::from_value(function_invocation)
                .map_err(serde::de::Error::custom)?,
            fee_transfer_invocation: serde_json::from_value(fee_transfer_invocation)
                .map_err(serde::de::Error::custom)?,
            signature,
        })
    }
}

#[cfg(test)]
impl RpcState {
    pub fn get_transaction_trace(&self, hash: Felt252) -> TransactionTrace {
        let chain_name = self.get_chain_name();
        let response = ureq::get(&format!(
            "https://{}.starknet.io/feeder_gateway/get_transaction_trace",
            chain_name
        ))
        .query("transactionHash", &format!("0x{}", hash.to_str_radix(16)))
        .call()
        .unwrap();

        serde_json::from_str(&response.into_string().unwrap()).unwrap()
    }

    fn get_chain_name(&self) -> String {
        match self.chain {
            RpcChain::MainNet => "alpha-mainnet".to_string(),
            RpcChain::TestNet => "alpha4".to_string(),
            RpcChain::TestNet2 => "alpha4-2".to_string(),
        }
    }

    pub fn get_block_info(
        &self,
        fee_token_address: Address,
        gas_price_u64: u64,
    ) -> starknet_in_rust::state::BlockInfo {
        let get_block_info_params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getBlockWithTxHashes",
            "params": [self.block.to_value()],
            "id": 1
        });

        let block_info: serde_json::Value = self.rpc_call(&get_block_info_params).unwrap();

        starknet_in_rust::state::BlockInfo {
            block_number: block_info["result"]["block_number"]
                .to_string()
                .parse::<u64>()
                .unwrap(),
            block_timestamp: block_info["result"]["timestamp"]
                .to_string()
                .parse::<u64>()
                .unwrap(),
            gas_price: gas_price_u64,
            sequencer_address: fee_token_address,
        }
    }
}

impl StateReader for RpcState {
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getClass",
            "params": [self.block.to_value(), format!("0x{}", Felt252::from_bytes_be(class_hash).to_str_radix(16))],
            "id": 1
        });

        let response: RpcResponseProgram = self
            .rpc_call(&params)
            .map_err(|err| StateError::CustomError(err.to_string()))?;

        Ok(CompiledClass::from(response.result))
    }

    fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError> {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getClassHashAt",
            "params": [self.block.to_value(), format!("0x{}", contract_address.0.to_str_radix(16))],
            "id": 1
        });

        let resp: RpcResponseFelt252 = self
            .rpc_call(&params)
            .map_err(|err| StateError::CustomError(err.to_string()))?;

        Ok(resp.result.to_be_bytes())
    }

    fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError> {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getNonce",
            "params": [self.block.to_value(), format!("0x{}", contract_address.0.to_str_radix(16))],
            "id": 1
        });

        let resp: RpcResponseFelt252 = self
            .rpc_call(&params)
            .map_err(|err| StateError::CustomError(err.to_string()))?;

        Ok(resp.result)
    }

    fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
        let params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getStorageAt",
            "params": [format!("0x{}", storage_entry.0 .0.to_str_radix(16)), format!(
                "0x{}",
                Felt252::from_bytes_be(&storage_entry.1).to_str_radix(16)
            ), self.block.to_value()],
            "id": 1
        });

        let resp: RpcResponseFelt252 = self
            .rpc_call(&params)
            .map_err(|err| StateError::CustomError(err.to_string()))?;

        Ok(resp.result)
    }

    fn get_compiled_class_hash(
        &self,
        _class_hash: &ClassHash,
    ) -> Result<CompiledClassHash, StateError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
    use starknet_in_rust::{
        definitions::{
            block_context::{BlockContext, StarknetChainId, StarknetOsConfig},
            constants::{
                DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS,
                DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
                DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT, DEFAULT_INVOKE_TX_MAX_N_STEPS,
                DEFAULT_VALIDATE_MAX_N_STEPS, EXECUTE_ENTRY_POINT_SELECTOR,
            },
        },
        felt::felt_str,
        state::cached_state::CachedState,
        transaction::InvokeFunction,
    };
    use std::{collections::HashMap, sync::Arc};

    #[test]
    fn test_get_contract_class_cairo1() {
        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );
        // This belongs to
        // https://starkscan.co/class/0x0298e56befa6d1446b86ed5b900a9ba51fd2faa683cd6f50e8f833c0fb847216
        // which is cairo1.0

        let class_hash = felt_str!(
            "0298e56befa6d1446b86ed5b900a9ba51fd2faa683cd6f50e8f833c0fb847216",
            16
        );
        rpc_state
            .get_contract_class(&class_hash.to_be_bytes())
            .unwrap();
    }

    #[test]
    fn test_get_contract_class_cairo0() {
        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );

        let class_hash = felt_str!(
            "025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918",
            16
        );
        rpc_state
            .get_contract_class(&class_hash.to_be_bytes())
            .unwrap();
    }

    #[test]
    fn test_get_class_hash_at() {
        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );
        let address = Address(felt_str!(
            "00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9",
            16
        ));
        assert_eq!(
            rpc_state.get_class_hash_at(&address).unwrap(),
            felt_str!(
                "025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918",
                16
            )
            .to_be_bytes()
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
        let address = Address(felt_str!(
            "07185f2a350edcc7ea072888edb4507247de23e710cbd56084c356d265626bea",
            16
        ));
        assert_eq!(
            rpc_state.get_nonce_at(&address).unwrap(),
            felt_str!("0", 16)
        );
    }

    #[test]
    fn test_get_storage_at() {
        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );
        let storage_entry = (
            Address(felt_str!(
                "00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9",
                16
            )),
            [0; 32],
        );
        assert_eq!(
            rpc_state.get_storage_at(&storage_entry).unwrap(),
            felt_str!("0", 16)
        );
    }

    #[test]
    fn test_invoke_execute() {
        let contract_address = Address(felt_str!(
            "06fcccb8c9c5bc490600d0d3a95134d3b2aacec7461fc1930178215803fa8d0c",
            16
        ));
        let entry_point_selector = EXECUTE_ENTRY_POINT_SELECTOR.clone();

        let max_fee = 103000000000000;
        let version = felt_str!("100000000000000000000000000000001", 16);

        let calldata = vec![
            felt_str!("1", 16),
            felt_str!(
                "49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
                16
            ),
            felt_str!(
                "83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                16
            ),
            felt_str!("0", 16),
            felt_str!("3", 16),
            felt_str!("3", 16),
            felt_str!(
                "54ae4dbc24999badc9a161f6f4b72156ca7da92da93046fcbb48680a324ac7c",
                16
            ),
            felt_str!("26f00fdabd0000", 16),
            felt_str!("0", 16),
        ];

        let signature = vec![
            felt_str!(
                "63cdad41f8f99362b181296492597edef76083a23a71e890c150eda0a848ce2",
                16
            ),
            felt_str!(
                "3064c7d20438426f1384ddb09cc2bdc1304cfc5dd9d7f7c46de8173f2bc71cf",
                16
            ),
        ];

        let nonce = Some(felt_str!("8"));

        let internal_invoke_function = InvokeFunction::new_with_tx_hash(
            contract_address,
            entry_point_selector,
            max_fee,
            version,
            calldata,
            signature,
            nonce,
            felt_str!(
                "014640564509873cf9d24a311e1207040c8b60efd38d96caef79855f0b0075d5",
                16
            ),
        )
        .unwrap()
        .create_for_simulation(false, false, true, false); // we could include the fee transfer by setting up correctly the BlockContext

        // Instantiate CachedState
        let state_reader = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Number(serde_json::to_value(90_006).unwrap()),
        );

        let mut state = CachedState::new(Arc::new(state_reader), None, None);

        let _result = internal_invoke_function
            .execute(&mut state, &BlockContext::default(), 0)
            .unwrap();
    }

    /// Invoke transaction test using the transaction:
    /// https://starkscan.co/tx/0x06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955
    #[test]
    fn test_invoke_mainnet_0x06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955() {
        // Tx Hash without the "0x" prefix.
        let tx_hash_str = "06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955";

        // Retrieve the transaction information from the RPC endpoint.
        let rpc_state = RpcState::new(RpcChain::MainNet, BlockValue::Number(90003.into()));
        let get_tx_params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getTransactionByHash",
            "params": [format!("0x{}", tx_hash_str)],
            "id": 1
        });
        let tx_mainnet: serde_json::Value = rpc_state.rpc_call(&get_tx_params).unwrap();
        let _get_block_info_params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getBlockWithTxHashes",
            "params": [rpc_state.block.to_value()],
            "id": 1
        });

        // Convert returned data from the tx to our types.
        let tx_hash = felt_str!(format!("{}", tx_hash_str), 16);
        let contract_address = Address(felt_str!(
            tx_mainnet["result"]["sender_address"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16
        ));
        let entry_point_selector = EXECUTE_ENTRY_POINT_SELECTOR.clone();
        let max_fee = u128::from_str_radix(
            tx_mainnet["result"]["max_fee"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16,
        )
        .unwrap();
        let version = felt_str!(
            tx_mainnet["result"]["version"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16
        );
        let calldata = tx_mainnet["result"]["calldata"]
            .as_array()
            .unwrap()
            .iter()
            .map(|felt_as_value| {
                felt_str!(
                    felt_as_value.as_str().unwrap().strip_prefix("0x").unwrap(),
                    16
                )
            })
            .collect::<Vec<Felt252>>();
        let signature = tx_mainnet["result"]["signature"]
            .as_array()
            .unwrap()
            .iter()
            .map(|felt_as_value| {
                felt_str!(
                    felt_as_value.as_str().unwrap().strip_prefix("0x").unwrap(),
                    16
                )
            })
            .collect::<Vec<Felt252>>();
        let nonce = Some(felt_str!(
            tx_mainnet["result"]["nonce"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16
        ));

        // Create InvokeFunction with the converted data.
        let internal_invoke_function = InvokeFunction::new_with_tx_hash(
            contract_address,
            entry_point_selector,
            max_fee,
            version,
            calldata,
            signature,
            nonce,
            tx_hash,
        )
        .unwrap()
        .create_for_simulation(false, false, false, false);

        // Instantiate CachedState
        let state_reader = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Number(serde_json::to_value(90_002).unwrap()),
        );

        let mut state = CachedState::new(Arc::new(state_reader), None, None);

        // BlockContext with mainnet data.
        // TODO look how to get this value from RPC call.
        let gas_price_str = "13575501577";
        let gas_price_u128 = gas_price_str.parse::<u128>().unwrap();
        let gas_price_u64 = gas_price_str.parse::<u64>().unwrap();

        let fee_token_address = Address(felt_str!(
            "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
            16
        ));
        let starknet_os_config = StarknetOsConfig::new(
            StarknetChainId::MainNet.to_felt(),
            fee_token_address.clone(),
            gas_price_u128,
        );
        let block_info = rpc_state.get_block_info(fee_token_address, gas_price_u64);

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

        let _result = internal_invoke_function
            .execute(&mut state, &block_context, 0)
            .unwrap();
    }

    /// Invoke transaction test using the transaction:
    /// https://testnet.starkscan.co/tx/0x074dab0828ec1b6cfde5188c41d41af1c198192a7d118217f95a802aa923dacf
    #[test]
    fn test_invoke_mainnet_0x074dab0828ec1b6cfde5188c41d41af1c198192a7d118217f95a802aa923dacf() {
        // Tx Hash without the "0x" prefix.
        let tx_hash_str = "074dab0828ec1b6cfde5188c41d41af1c198192a7d118217f95a802aa923dacf";

        let tx_hash = felt_str!(format!("{}", tx_hash_str), 16);
        let contract_address = Address(felt_str!(
            "02dc97a4cc28fa95be6a6ae92cc1a2e3fb07eb6866c65e039daa75391806c254",
            16
        ));
        let entry_point_selector = EXECUTE_ENTRY_POINT_SELECTOR.clone();
        let max_fee = 10811422177042;
        let version = felt_str!("1", 16);
        let calldata = [
            felt_str!("1", 16),
            felt_str!(
                "12d37c39a385cf56801b57626e039147abce1183ce55e419e4296398b81d9e2",
                16
            ),
            felt_str!(
                "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
                16
            ),
            felt_str!("0", 16),
            felt_str!("3", 16),
            felt_str!("3", 16),
            felt_str!("1", 16),
            felt_str!("1", 16),
            felt_str!("10", 16),
        ]
        .to_vec();

        let signature = [
            felt_str!(
                "3043488d10251917860d388304d993d259c750f28f147bf986e2f6e6af28df2",
                16
            ),
            felt_str!(
                "24bfcbb6be97350eaeb42f2d81dd66efa92ef725c2ad3127750b67ffd50508d",
                16
            ),
        ]
        .to_vec();
        let nonce = Some(felt_str!("4", 16));

        // Create InvokeFunction with the converted data.
        let internal_invoke_function = InvokeFunction::new_with_tx_hash(
            contract_address,
            entry_point_selector,
            max_fee,
            version,
            calldata,
            signature,
            nonce,
            tx_hash,
        )
        .unwrap()
        .create_for_simulation(false, false, false, false);

        // Instantiate CachedState
        let state_reader = RpcState::new(
            RpcChain::TestNet,
            BlockValue::Number(serde_json::to_value(838683).unwrap()),
        );

        let mut state = CachedState::new(Arc::new(state_reader), None, None);

        // BlockContext with mainnet data.
        // TODO look how to get this value from RPC call.
        let gas_price_str = "2888823561";
        let gas_price_u128 = gas_price_str.parse::<u128>().unwrap();
        let gas_price_u64 = gas_price_str.parse::<u64>().unwrap();

        let fee_token_address = Address(felt_str!(
            "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
            16
        ));
        let starknet_os_config = StarknetOsConfig::new(
            StarknetChainId::TestNet.to_felt(),
            fee_token_address.clone(),
            gas_price_u128,
        );

        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );
        let block_info = rpc_state.get_block_info(fee_token_address, gas_price_u64);

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

        let _result = internal_invoke_function
            .execute(&mut state, &block_context, 0)
            .unwrap();
    }

    /// Invoke transaction test using the transaction:
    /// https://testnet-2.starkscan.co/tx/0x019feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc
    #[test]
    fn test_invoke_testnet2_0x019feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc() {
        // Tx Hash without the "0x" prefix.
        let tx_hash_str = "019feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc";

        let tx_hash = felt_str!(format!("{}", tx_hash_str), 16);
        let entry_point_selector = EXECUTE_ENTRY_POINT_SELECTOR.clone();
        let max_fee = 10811422177042;
        let version = felt_str!("1", 16);

        let calldata = [
            felt_str!("1", 16),
            felt_str!(
                "690c876e61beda61e994543af68038edac4e1cb1990ab06e52a2d27e56a1232",
                16
            ),
            felt_str!(
                "1f24f689ced5802b706d7a2e28743fe45c7bfa37431c97b1c766e9622b65573",
                16
            ),
            felt_str!("0", 16),
            felt_str!("9", 16),
            felt_str!("9", 16),
            felt_str!("4", 16),
            felt_str!("4254432d55534443", 16),
            felt_str!("f02e7324ecbd65ce267", 16),
            felt_str!("5754492d55534443", 16),
            felt_str!("8e13050d06d8f514c", 16),
            felt_str!("4554482d55534443", 16),
            felt_str!("f0e4a142c3551c149d", 16),
            felt_str!("4a50592d55534443", 16),
            felt_str!("38bd34c31a0a5c", 16),
        ]
        .to_vec();

        let signature = [
            felt_str!(
                "ffab1c47d8d5e5b76bdcc4af79e98205716c36b440f20244c69599a91ace58",
                16
            ),
            felt_str!(
                "6aa48a0906c9c1f7381c1a040c043b649eeac1eea08f24a9d07813f6b1d05fe",
                16
            ),
        ]
        .to_vec();
        let nonce = Some(16930.into());

        // Instantiate CachedState
        let state_reader = RpcState::new(
            RpcChain::TestNet2,
            BlockValue::Number(serde_json::to_value(123001).unwrap()),
        );

        let get_tx_params = ureq::json!({
            "jsonrpc": "2.0",
            "method": "starknet_getTransactionByHash",
            "params": [format!("0x{}", tx_hash_str)],
            "id": 1
        });
        let tx_testnet2: serde_json::Value = state_reader.rpc_call(&get_tx_params).unwrap();

        let contract_address = Address(felt_str!(
            tx_testnet2["result"]["sender_address"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16
        ));

        // Create InvokeFunction with the converted data.
        let internal_invoke_function = InvokeFunction::new_with_tx_hash(
            contract_address,
            entry_point_selector,
            max_fee,
            version,
            calldata,
            signature,
            nonce,
            tx_hash,
        )
        .unwrap()
        .create_for_simulation(true, false, true, true);

        // BlockContext with mainnet data.
        // TODO look how to get this value from RPC call.
        let gas_price_str = "2888823561";
        let gas_price_u128 = gas_price_str.parse::<u128>().unwrap();

        let gas_price_u64 = gas_price_str.parse::<u64>().unwrap();

        let fee_token_address = Address(felt_str!(
            "49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
            16
        ));
        let rpc_state = RpcState::new(
            RpcChain::MainNet,
            BlockValue::Tag(serde_json::to_value("latest").unwrap()),
        );

        let starknet_os_config = StarknetOsConfig::new(
            StarknetChainId::TestNet2.to_felt(),
            fee_token_address.clone(),
            gas_price_u128,
        );

        let block_info = rpc_state.get_block_info(fee_token_address, gas_price_u64);

        let mut state = CachedState::new(Arc::new(state_reader), None, None);

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

        let _result = internal_invoke_function
            .execute(&mut state, &block_context, 0)
            .unwrap();
    }
    // https://alpha4-2.starknet.io/feeder_gateway/get_transaction_trace?transactionHash=0x019feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc
    #[test]
    fn test_get_transaction_trace() {
        let state_reader = RpcState::new(
            RpcChain::TestNet2,
            BlockValue::Number(serde_json::to_value(838683).unwrap()),
        );

        let tx_hash_str = "19feb888a2d53ffddb7a1750264640afab8e9c23119e648b5259f1b5e7d51bc";
        let tx_hash = felt_str!(format!("{}", tx_hash_str), 16);

        let tx_trace = state_reader.get_transaction_trace(tx_hash);

        assert_eq!(
            tx_trace.signature,
            vec![
                felt_str!(
                    "ffab1c47d8d5e5b76bdcc4af79e98205716c36b440f20244c69599a91ace58",
                    16
                ),
                felt_str!(
                    "6aa48a0906c9c1f7381c1a040c043b649eeac1eea08f24a9d07813f6b1d05fe",
                    16
                ),
            ]
        );

        assert_eq!(
            tx_trace.validate_invocation.calldata,
            vec![
                felt_str!("1", 16),
                felt_str!(
                    "690c876e61beda61e994543af68038edac4e1cb1990ab06e52a2d27e56a1232",
                    16
                ),
                felt_str!(
                    "1f24f689ced5802b706d7a2e28743fe45c7bfa37431c97b1c766e9622b65573",
                    16
                ),
                felt_str!("0", 16),
                felt_str!("9", 16),
                felt_str!("9", 16),
                felt_str!("4", 16),
                felt_str!("4254432d55534443", 16),
                felt_str!("f02e7324ecbd65ce267", 16),
                felt_str!("5754492d55534443", 16),
                felt_str!("8e13050d06d8f514c", 16),
                felt_str!("4554482d55534443", 16),
                felt_str!("f0e4a142c3551c149d", 16),
                felt_str!("4a50592d55534443", 16),
                felt_str!("38bd34c31a0a5c", 16),
            ]
        );
        assert_eq!(tx_trace.validate_invocation.retdata, vec![]);
        assert_eq!(
            tx_trace.validate_invocation.execution_resources,
            ExecutionResources {
                n_steps: 790,
                n_memory_holes: 51,
                builtin_instance_counter: HashMap::from([
                    ("range_check_builtin".to_string(), 20),
                    ("ecdsa_builtin".to_string(), 1),
                    ("pedersen_builtin".to_string(), 2),
                ]),
            }
        );

        assert_eq!(
            tx_trace.function_invocation.calldata,
            vec![
                felt_str!("1", 16),
                felt_str!(
                    "690c876e61beda61e994543af68038edac4e1cb1990ab06e52a2d27e56a1232",
                    16
                ),
                felt_str!(
                    "1f24f689ced5802b706d7a2e28743fe45c7bfa37431c97b1c766e9622b65573",
                    16
                ),
                felt_str!("0", 16),
                felt_str!("9", 16),
                felt_str!("9", 16),
                felt_str!("4", 16),
                felt_str!("4254432d55534443", 16),
                felt_str!("f02e7324ecbd65ce267", 16),
                felt_str!("5754492d55534443", 16),
                felt_str!("8e13050d06d8f514c", 16),
                felt_str!("4554482d55534443", 16),
                felt_str!("f0e4a142c3551c149d", 16),
                felt_str!("4a50592d55534443", 16),
                felt_str!("38bd34c31a0a5c", 16),
            ]
        );
        assert_eq!(tx_trace.function_invocation.retdata, vec![0.into()]);
        assert_eq!(
            tx_trace.function_invocation.execution_resources,
            ExecutionResources {
                n_steps: 2808,
                n_memory_holes: 136,
                builtin_instance_counter: HashMap::from([
                    ("range_check_builtin".to_string(), 49),
                    ("pedersen_builtin".to_string(), 14),
                ]),
            }
        );

        assert_eq!(
            tx_trace.fee_transfer_invocation.calldata,
            vec![
                felt_str!(
                    "1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8",
                    16
                ),
                felt_str!("2b0322a23ba4", 16),
                felt_str!("0", 16),
            ]
        );
        assert_eq!(tx_trace.fee_transfer_invocation.retdata, vec![1.into()]);
        assert_eq!(
            tx_trace.fee_transfer_invocation.execution_resources,
            ExecutionResources {
                n_steps: 586,
                n_memory_holes: 42,
                builtin_instance_counter: HashMap::from([
                    ("range_check_builtin".to_string(), 21),
                    ("pedersen_builtin".to_string(), 4),
                ]),
            }
        );
    }
}
