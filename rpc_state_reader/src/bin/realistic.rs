use cairo_vm::felt::felt_str;
use rpc_state_reader::{BlockValue, RpcChain, RpcState};
use starknet_in_rust::{
    definitions::{
        block_context::{BlockContext, StarknetChainId, StarknetOsConfig},
        constants::{
            DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS, DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
            DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT, DEFAULT_INVOKE_TX_MAX_N_STEPS,
            DEFAULT_VALIDATE_MAX_N_STEPS,
        },
    },
    state::cached_state::CachedState,
    utils::Address,
};
use std::sync::Arc;

fn main() {
    let tx_hash = "0x06da92cfbdceac5e5e94a1f40772d6c79d34f011815606742658559ec77b6955";
    let network = RpcChain::MainNet;
    let block_number = 90_002;
    let gas_price = 13572248835;

    let tx_hash = tx_hash.strip_prefix("0x").unwrap();

    // Instantiate the RPC StateReader and the CachedState
    let block = BlockValue::Number(serde_json::to_value(block_number).unwrap());
    let rpc_state = Arc::new(RpcState::new(network, block));
    let mut state = CachedState::new(rpc_state.clone(), None, None);

    let fee_token_address = Address(felt_str!(
        "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
        16
    ));

    let network: StarknetChainId = rpc_state.chain.into();
    let starknet_os_config = StarknetOsConfig::new(network.to_felt(), fee_token_address, gas_price);

    let block_info = rpc_state.get_block_info(starknet_os_config.clone());

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

    let tx = rpc_state.get_transaction(tx_hash);

    tx.execute(&mut state, &block_context, 0).unwrap();
}
