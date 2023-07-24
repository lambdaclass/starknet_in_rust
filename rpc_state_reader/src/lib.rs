use serde::{Deserialize, Deserializer};
use serde_json::json;
use starknet::core::types::ContractClass;
use starknet_in_rust::{
    core::errors::state_errors::StateError,
    felt::Felt252,
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{state_api::StateReader, state_cache::StorageEntry},
    utils::{Address, ClassHash, CompiledClassHash},
};
use std::env;
use thiserror::Error;
use serde_with::{serde_as, DeserializeAs};

/// State that implements [`StateReader`], using the RPC endpoints through Infura.
pub struct RpcState {
    chain: String,
    api_key: String,
    block: BlockValue,
}

#[derive(Debug, Error)]
enum RpcError {
    #[error("RPC call failed with error: {0}")]
    RpcCall(String),
}

#[allow(dead_code)]
enum BlockValue {
    /// String one of: ["latest", "pending"]
    BlockTag(serde_json::Value),
    /// Integer
    BlockNumber(serde_json::Value),
    /// String with format: 0x{felt252}
    BlockHash(serde_json::Value),
}

impl BlockValue {
    fn to_value(self: &Self) -> serde_json::Value {
        match self {
            BlockValue::BlockTag(block_tag) => block_tag.clone(),
            BlockValue::BlockNumber(block_number) => json!({ "block_number": block_number }),
            BlockValue::BlockHash(block_hash) => json!({ "block_hash": block_hash }),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RpcResponseProgram {
    result: ContractClass,
}

pub struct FeltHex;

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
    #[allow(dead_code)]
    fn new(chain: String, block: BlockValue) -> Self {
        Self {
            chain,
            api_key: env::var("INFURA_API_KEY").unwrap(),
            block,
        }
    }

    fn rpc_call<T: for<'a> Deserialize<'a>>(
        self: &Self,
        _rpc_method: String,
        params: &serde_json::Value,
    ) -> Result<T, RpcError> {
        let response = ureq::post(&format!(
            "https://{}.infura.io/v3/{}",
            self.chain, self.api_key
        ))
        .set("Content-Type", "application/json")
        .set("accept", "application/json")
        .send_json(params)
        .unwrap()
        .into_string()
        .unwrap();
        serde_json::from_str(&response).map_err(|err| RpcError::RpcCall(err.to_string()))
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
            .rpc_call("starknet_getClass".to_string(), &params)
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
            .rpc_call("starknet_getClassHashAt".to_string(), &params)
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
            .rpc_call("starknet_getNonce".to_string(), &params)
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
            .rpc_call("starknet_getStorageAt".to_string(), &params)
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
    use std::sync::Arc;

    use super::*;
    use starknet_in_rust::{
        definitions::{block_context::BlockContext, constants::EXECUTE_ENTRY_POINT_SELECTOR},
        felt::felt_str,
        state::cached_state::CachedState,
        transaction::{InvokeFunction, Transaction},
    };

    #[test]
    fn test_get_contract_class_cairo1() {
        let rpc_state = RpcState::new(
            "starknet-mainnet".to_string(),
            BlockValue::BlockTag(serde_json::to_value("latest").unwrap()),
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
            "starknet-mainnet".to_string(),
            BlockValue::BlockTag(serde_json::to_value("latest").unwrap()),
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
            "starknet-mainnet".to_string(),
            BlockValue::BlockTag(serde_json::to_value("latest").unwrap()),
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
            "starknet-mainnet".to_string(),
            BlockValue::BlockTag(serde_json::to_value("latest").unwrap()),
        );
        let address = Address(felt_str!(
            "00b081f7ba1efc6fe98770b09a827ae373ef2baa6116b3d2a0bf5154136573a9",
            16
        ));
        assert_eq!(
            rpc_state.get_nonce_at(&address).unwrap(),
            felt_str!("1", 16)
        );
    }

    #[test]
    fn test_get_storage_at() {
        let rpc_state = RpcState::new(
            "starknet-mainnet".to_string(),
            BlockValue::BlockTag(serde_json::to_value("latest").unwrap()),
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
            "0213887f63ac94d220d3e0e1052e1037e084ae683112116965335af5115f37cc",
            16
        ));
        let entry_point_selector = EXECUTE_ENTRY_POINT_SELECTOR.clone();

        let max_fee = 542063243332116;
        let version = felt_str!("100000000000000000000000000000001", 16);

        let calldata = vec![
            felt_str!("1", 16),
            felt_str!(
                "1b22f7a9d18754c994ae0ee9adb4628d414232e3ebd748c386ac286f86c3066",
                16
            ),
            felt_str!(
                "2f0b3c5710379609eb5495f1ecd348cb28167711b73609fe565a72734550354",
                16
            ),
            felt_str!("0", 16),
            felt_str!("7", 16),
            felt_str!("7", 16),
            felt_str!(
                "213887f63ac94d220d3e0e1052e1037e084ae683112116965335af5115f37cc",
                16
            ),
            felt_str!("d772d", 16),
            felt_str!("4", 16),
            felt_str!("7a120", 16),
            felt_str!("66591300", 16),
            felt_str!(
                "4404f9322daa95e6fa2bc4bd424e7ba45d18b117b7515e209531486b7479d70",
                16
            ),
            felt_str!(
                "2f1cae21f2618ac89b90e24c7b7316a471cabdb1655475648c5415007b94262",
                16
            ),
        ];

        let signature = vec![
            felt_str!(
                "20cb013c9848c0639d76861d69e527c4f1d315298a62731c794be7ebf82e857",
                16
            ),
            felt_str!(
                "6d250d217ac57658ac98b5df7ad52dce4f98180315ab76c3f36d787c92dc35a",
                16
            ),
        ];
        // let chain_id = StarknetChainId::Mainnet.to_felt();
        let nonce = Some(felt_str!("9"));

        let internal_invoke_function = Transaction::InvokeFunction(
            InvokeFunction::new_with_tx_hash(
                contract_address,
                entry_point_selector,
                max_fee,
                version,
                calldata,
                signature,
                nonce,
                felt_str!(
                    "02afa4f3399d11419b1ebc6b0af9abcb9c6dc25e5754f52522a16deba1971120",
                    16
                ),
            )
            .unwrap(),
        );

        // Instantiate CachedState
        let state_reader = RpcState::new(
            "starknet-mainnet".to_string(),
            BlockValue::BlockNumber(serde_json::to_value(69_999).unwrap()),
        );

        let mut state = CachedState::new(Arc::new(state_reader), None, None);

        let _result = internal_invoke_function
            .execute(&mut state, &BlockContext::default(), 0)
            .unwrap();
    }
}
