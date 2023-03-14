use crate::{business_logic::state::state_api_objects::BlockInfo, utils::Address};
use felt::Felt;
use getset::{CopyGetters, Getters, MutGetters};
use num_traits::Zero;
use std::collections::HashMap;

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
    pub fn to_felt(self) -> Felt {
        Felt::from_bytes_be(self.to_string().as_bytes())
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

#[derive(Clone, Debug, CopyGetters, Getters, MutGetters)]
pub struct StarknetGeneralConfig {
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) starknet_os_config: StarknetOsConfig,
    pub(crate) _contract_storage_commitment_tree_height: u64,
    _global_state_commitment_tree_height: u64,
    pub(crate) cairo_resource_fee_weights: HashMap<String, f64>,
    #[get_copy = "pub"]
    pub(crate) invoke_tx_max_n_steps: u64,
    pub(crate) validate_max_n_steps: u64,
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) block_info: BlockInfo,
}

impl StarknetGeneralConfig {
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn new(
        starknet_os_config: StarknetOsConfig,
        _contract_storage_commitment_tree_height: u64,
        _global_state_commitment_tree_height: u64,
        invoke_tx_max_n_steps: u64,
        block_info: BlockInfo,
    ) -> Self {
        Self {
            starknet_os_config,
            _contract_storage_commitment_tree_height,
            _global_state_commitment_tree_height,
            invoke_tx_max_n_steps,
            cairo_resource_fee_weights: HashMap::new(),
            validate_max_n_steps: 0,
            block_info,
        }
    }
}

impl Default for StarknetGeneralConfig {
    fn default() -> Self {
        Self {
            starknet_os_config: StarknetOsConfig {
                chain_id: StarknetChainId::TestNet,
                fee_token_address: Address(Felt::zero()),
                gas_price: 0,
            },
            _contract_storage_commitment_tree_height: 0,
            _global_state_commitment_tree_height: 0,
            invoke_tx_max_n_steps: 0,
            cairo_resource_fee_weights: HashMap::new(),
            validate_max_n_steps: 0,
            block_info: BlockInfo::empty(Address::default()),
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
