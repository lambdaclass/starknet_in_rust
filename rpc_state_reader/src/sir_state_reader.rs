use std::sync::Arc;

use cairo_vm::felt::{felt_str, Felt252};
use starknet_api::{
    block::BlockNumber,
    core::{ClassHash as SNClassHash, ContractAddress, PatriciaKey},
    hash::{StarkFelt, StarkHash},
    stark_felt,
    state::StorageKey,
    transaction::{Transaction as SNTransaction, TransactionHash},
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
    execution::TransactionExecutionInfo,
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{
        cached_state::{CachedState, ContractClassCache},
        state_api::StateReader,
        state_cache::StorageEntry,
        BlockInfo,
    },
    transaction::InvokeFunction,
    utils::{Address, ClassHash},
};

use crate::{
    rpc_state::{RpcBlockInfo, RpcChain, RpcState, RpcTransactionReceipt, TransactionTrace},
    rpc_state_errors::RpcStateError,
};

#[derive(Debug)]
pub struct RpcStateReader(RpcState);

impl RpcStateReader {
    pub fn new(state: RpcState) -> Self {
        Self(state)
    }
}

impl StateReader for RpcStateReader {
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        let hash = SNClassHash(StarkHash::new(*class_hash).unwrap());
        let contract_class = self
            .0
            .get_contract_class(&hash)
            .ok_or(StateError::MissingCasmClass(*class_hash))?;
        Ok(CompiledClass::from(contract_class))
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
        Ok(*class_hash)
    }
}

#[allow(unused)]
pub fn execute_tx_configurable(
    tx_hash: &str,
    network: RpcChain,
    block_number: BlockNumber,
    skip_validate: bool,
    skip_nonce_check: bool,
) -> Result<
    (
        TransactionExecutionInfo,
        TransactionTrace,
        RpcTransactionReceipt,
    ),
    RpcStateError,
> {
    let fee_token_address = Address(felt_str!(
        "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
        16
    ));

    let tx_hash = tx_hash.strip_prefix("0x").unwrap();

    let rpc_state = RpcState::new_infura(network, block_number.into())?;
    // Instantiate the RPC StateReader and the CachedState
    let rpc_reader = RpcStateReader(rpc_state);
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
        } = rpc_reader.0.get_block_info()?;

        let block_number = block_number.0;
        let block_timestamp = block_timestamp.0;
        let sequencer_address = Address(Felt252::from_bytes_be(sequencer_address.0.key().bytes()));

        BlockInfo {
            block_number,
            block_timestamp,
            gas_price,
            sequencer_address,
        }
    };

    // Get transaction before giving ownership of the reader
    let tx_hash = TransactionHash(stark_felt!(tx_hash));
    let tx = match rpc_reader.0.get_transaction(&tx_hash)? {
        SNTransaction::Invoke(tx) => InvokeFunction::from_invoke_transaction(tx, chain_id)
            .unwrap()
            .create_for_simulation(skip_validate, false, false, false, skip_nonce_check),
        _ => unimplemented!(),
    };

    let trace = rpc_reader.0.get_transaction_trace(&tx_hash)?;
    let receipt = rpc_reader.0.get_transaction_receipt(&tx_hash)?;

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

    Ok((
        tx.execute(&mut state, &block_context, u128::MAX).unwrap(),
        trace,
        receipt,
    ))
}

pub fn execute_tx(
    tx_hash: &str,
    network: RpcChain,
    block_number: BlockNumber,
) -> Result<
    (
        TransactionExecutionInfo,
        TransactionTrace,
        RpcTransactionReceipt,
    ),
    RpcStateError,
> {
    execute_tx_configurable(tx_hash, network, block_number, false, false)
}

pub fn execute_tx_without_validate(
    tx_hash: &str,
    network: RpcChain,
    block_number: BlockNumber,
) -> Result<
    (
        TransactionExecutionInfo,
        TransactionTrace,
        RpcTransactionReceipt,
    ),
    RpcStateError,
> {
    execute_tx_configurable(tx_hash, network, block_number, true, true)
}
