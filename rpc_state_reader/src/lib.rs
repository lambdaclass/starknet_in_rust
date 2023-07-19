use serde::Deserialize;
use starknet_in_rust::SierraContractClass;
use starknet_in_rust::{
    core::errors::state_errors::StateError,
    felt::{felt_str, Felt252},
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{state_api::StateReader, state_cache::StorageEntry},
    utils::{Address, ClassHash, CompiledClassHash},
};
use std::env;

pub struct RpcState {
    chain: String,
    api_key: String,
}

impl RpcState {
    #[allow(dead_code)]
    fn new(chain: String) -> Self {
        Self {
            chain,
            api_key: env::var("INFURA_API_KEY").unwrap(),
        }
    }

    fn rpc_call<T: for<'a> Deserialize<'a>>(
        self: &Self,
        rpc_method: String,
        params: &[String],
    ) -> T {
        ureq::post(&format!(
            "https://{}.infura.io/v3/{}",
            self.chain, self.api_key
        ))
        .set("Content-Type", "application/json")
        .send_json(ureq::json!({
            "jsonrpc": "2.0",
            "method": rpc_method,
            "params": params,
            "id": 1
        }))
        .unwrap()
        .into_json()
        .unwrap()
    }
}

#[derive(Deserialize, Debug)]
struct RpcResponseString {
    result: String,
}

#[derive(Deserialize, Debug)]
struct RpcResponseValue {
    result: SierraContractClass,
}

impl StateReader for RpcState {
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        let _resp: RpcResponseValue = self.rpc_call(
            "starknet_getClass".to_string(),
            &[
                "latest".to_owned(),
                format!("0x{}", Felt252::from_bytes_be(class_hash).to_str_radix(16)),
            ],
        );
        println!("SierraContractClass {:?}", _resp.result);
        todo!()
    }

    fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError> {
        let resp: RpcResponseString = self.rpc_call(
            "starknet_getClassHashAt".to_string(),
            &[
                "latest".to_string(),
                format!("0x{}", contract_address.0.to_str_radix(16)),
            ],
        );

        let class_hash_as_hex = felt_str!(resp.result.strip_prefix("0x").unwrap(), 16);
        Ok(class_hash_as_hex.to_be_bytes())
    }

    fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError> {
        let resp: RpcResponseString = self.rpc_call(
            "starknet_getNonce".to_string(),
            &[
                "latest".to_string(),
                format!("0x{}", contract_address.0.to_str_radix(16)),
            ],
        );

        let nonce = felt_str!(resp.result.strip_prefix("0x").unwrap(), 16);
        Ok(nonce)
    }

    fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
        let resp: RpcResponseString = self.rpc_call(
            "starknet_getStorageAt".to_string(),
            &[
                format!("0x{}", storage_entry.0 .0.to_str_radix(16)),
                format!(
                    "0x{}",
                    Felt252::from_bytes_be(&storage_entry.1).to_str_radix(16)
                ),
                "latest".to_string(),
            ],
        );

        let storage_value = felt_str!(resp.result.strip_prefix("0x").unwrap(), 16);
        Ok(storage_value)
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

    #[test]
    fn test_get_contract_class_cairo1() {
        let rpc_state = RpcState::new("starknet-mainnet".to_string());
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
        let rpc_state = RpcState::new("starknet-mainnet".to_string());
        // This belongs to
        // https://starkscan.co/class/0x00d0e183745e9dae3e4e78a8ffedcce0903fc4900beace4e0abf192d4c202da3
        // which is cairo0

        let class_hash = felt_str!(
            "00d0e183745e9dae3e4e78a8ffedcce0903fc4900beace4e0abf192d4c202da3",
            16
        );
        rpc_state
            .get_contract_class(&class_hash.to_be_bytes())
            .unwrap();
    }

    #[test]
    fn test_get_class_hash_at() {
        let rpc_state = RpcState::new("starknet-mainnet".to_string());
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
        let rpc_state = RpcState::new("starknet-mainnet".to_string());
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
        let rpc_state = RpcState::new("starknet-mainnet".to_string());
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
}
