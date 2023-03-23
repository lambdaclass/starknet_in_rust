use crate::{business_logic::state::state_api_objects::BlockInfo, utils::Address};
use felt::Felt252;
use getset::{CopyGetters, Getters, MutGetters};
use std::collections::HashMap;

use super::constants::{
    DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS, DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
    DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT, DEFAULT_INVOKE_TX_MAX_N_STEPS,
    DEFAULT_SEQUENCER_ADDRESS, DEFAULT_STARKNET_OS_CONFIG, DEFAULT_VALIDATE_MAX_N_STEPS,
};

#[derive(Debug, Clone, Copy)]
pub enum StarknetChainId {
    MainNet,
    TestNet,
    TestNet2,
}

impl ToString for StarknetChainId {
    fn to_string(&self) -> String {
        match self {
            StarknetChainId::MainNet => "SN_MAIN",
            StarknetChainId::TestNet => "SN_GOERLI",
            StarknetChainId::TestNet2 => "SN_GOERLI2",
        }
        .to_string()
    }
}

impl StarknetChainId {
    pub fn to_felt(self) -> Felt252 {
        Felt252::from_bytes_be(self.to_string().as_bytes())
    }
}

#[derive(Debug, Clone, Getters, MutGetters)]
pub struct StarknetOsConfig {
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) chain_id: StarknetChainId,
    #[get = "pub"]
    pub(crate) fee_token_address: Address,
    pub(crate) gas_price: u64,
}

impl StarknetOsConfig {
    pub fn new(chain_id: StarknetChainId, fee_token_address: Address, gas_price: u64) -> Self {
        StarknetOsConfig {
            chain_id,
            fee_token_address,
            gas_price,
        }
    }
}

impl Default for StarknetOsConfig {
    fn default() -> Self {
        DEFAULT_STARKNET_OS_CONFIG.clone()
    }
}

#[derive(Clone, Debug, CopyGetters, Getters, MutGetters)]
pub struct StarknetGeneralConfig {
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) starknet_os_config: StarknetOsConfig,
    #[get_copy = "pub"]
    pub(crate) contract_storage_commitment_tree_height: u64,
    #[get_copy = "pub"]
    global_state_commitment_tree_height: u64,
    #[get = "pub"]
    pub(crate) cairo_resource_fee_weights: HashMap<String, f64>,
    #[get_copy = "pub"]
    pub(crate) invoke_tx_max_n_steps: u64,
    #[get_copy = "pub"]
    pub(crate) validate_max_n_steps: u64,
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) block_info: BlockInfo,
}

impl StarknetGeneralConfig {
    pub fn new(
        starknet_os_config: StarknetOsConfig,
        contract_storage_commitment_tree_height: u64,
        global_state_commitment_tree_height: u64,
        cairo_resource_fee_weights: HashMap<String, f64>,
        invoke_tx_max_n_steps: u64,
        validate_max_n_steps: u64,
        block_info: BlockInfo,
    ) -> Self {
        Self {
            starknet_os_config,
            contract_storage_commitment_tree_height,
            global_state_commitment_tree_height,
            invoke_tx_max_n_steps,
            cairo_resource_fee_weights,
            validate_max_n_steps,
            block_info,
        }
    }
}

impl Default for StarknetGeneralConfig {
    fn default() -> Self {
        Self {
            starknet_os_config: Default::default(),
            contract_storage_commitment_tree_height:
                DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
            global_state_commitment_tree_height: DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT,
            invoke_tx_max_n_steps: DEFAULT_INVOKE_TX_MAX_N_STEPS,
            cairo_resource_fee_weights: DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS.clone(),
            validate_max_n_steps: DEFAULT_VALIDATE_MAX_N_STEPS,
            block_info: BlockInfo::empty(DEFAULT_SEQUENCER_ADDRESS.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use felt::felt_str;

    #[test]
    fn starknet_chain_to_felt() {
        assert_eq!(
            felt_str!("23448594291968334"),
            StarknetChainId::MainNet.to_felt()
        );
        assert_eq!(
            felt_str!("1536727068981429685321"),
            StarknetChainId::TestNet.to_felt()
        );
        assert_eq!(
            felt_str!("393402129659245999442226"),
            StarknetChainId::TestNet2.to_felt()
        );
    }
}
