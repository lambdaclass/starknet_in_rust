use cairo_vm::felt::{felt_str, Felt252};
use rpc_state_reader::rpc_state::{BlockValue, RpcBlockInfo, RpcChain, RpcState};
use starknet_api::{
    block::BlockNumber,
    core::{ClassHash as SNClassHash, ContractAddress, PatriciaKey},
    hash::{StarkFelt, StarkHash},
    stark_felt,
    state::StorageKey,
    transaction::TransactionHash,
};
use starknet_in_rust::{
    core::errors::state_errors::StateError,
    definitions::{
        block_context::{BlockContext, StarknetChainId, StarknetOsConfig},
        constants::{
            DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS, DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
            DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT, DEFAULT_INVOKE_TX_MAX_N_STEPS,
            DEFAULT_VALIDATE_MAX_N_STEPS,
        },
    },
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{
        cached_state::CachedState, state_api::StateReader, state_cache::StorageEntry, BlockInfo,
    },
    transaction::{InvokeFunction, Transaction},
    utils::{Address, ClassHash},
};
use std::{collections::HashMap, sync::Arc};

pub struct RpcStateReader(RpcState);

impl StateReader for RpcStateReader {
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        let hash = SNClassHash(StarkHash::new(*class_hash).unwrap());
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
        let address =
            ContractAddress(PatriciaKey::try_from(StarkHash::new(*class_hash).unwrap()).unwrap());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.0.get_class_hash_at(&address).0.bytes());
        Ok(bytes)
    }
}

impl AsRef<RpcState> for RpcStateReader {
    fn as_ref(&self) -> &RpcState {
        &self.0
    }
}

impl AsMut<RpcState> for RpcStateReader {
    fn as_mut(&mut self) -> &mut RpcState {
        &mut self.0
    }
}

fn main() {
    let tx_hash = TransactionHash(stark_felt!(
        "0x06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955"
    ));
    let network = RpcChain::MainNet;
    let block_number = 90_002;
    let gas_price = 13572248835;

    // Instantiate the RPC StateReader and the CachedState
    let block = BlockValue::Number(BlockNumber(block_number));
    let rpc_state = Arc::new(RpcStateReader(RpcState::new_infura(network, block)));
    let mut state = CachedState::new(rpc_state.clone(), HashMap::default());

    let fee_token_address = Address(felt_str!(
        "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
        16
    ));

    let network: StarknetChainId = StarknetChainId::MainNet;
    let starknet_os_config = StarknetOsConfig::new(network.to_felt(), fee_token_address, gas_price);

    let block_info = rpc_state.0.get_block_info();

    let block_context = BlockContext::new(
        starknet_os_config,
        DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
        DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT,
        DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS.clone(),
        DEFAULT_INVOKE_TX_MAX_N_STEPS,
        DEFAULT_VALIDATE_MAX_N_STEPS,
        {
            let RpcBlockInfo {
                block_number,
                block_timestamp,
                sequencer_address,
                ..
            } = block_info;

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
        },
        Default::default(),
        true,
    );

    let tx: Transaction = match rpc_state.0.get_transaction(&tx_hash) {
        starknet_api::transaction::Transaction::Invoke(tx) => Transaction::InvokeFunction(
            InvokeFunction::from_invoke_transaction(tx, network).unwrap(),
        ),
        _ => panic!("This transaction should be an INVOKE transaction"),
    };

    tx.execute(&mut state, &block_context, 0).unwrap();
}
