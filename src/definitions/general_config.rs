use std::collections::HashMap;
use crate::{business_logic::state::state_api_objects::BlockInfo, utils::Address};
use felt::Felt;
use getset::{CopyGetters, MutGetters};
use num_traits::Zero;

use super::error::StarknetChainIdError;

#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum StarknetChainId {
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    MainNet,
    TestNet,
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
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
    pub(crate) fn to_felt(self) -> Felt {
        Felt::from_bytes_be(self.to_string().as_bytes())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StarknetOsConfig {
    pub(crate) chain_id: StarknetChainId,
    pub(crate) fee_token_address: Address,
    pub(crate) gas_price: u64,
}

#[derive(Clone, Debug, CopyGetters, MutGetters)]
pub struct StarknetGeneralConfig {
    pub(crate) starknet_os_config: StarknetOsConfig,
    pub(crate) contract_storage_commitment_tree_height: u64,
    global_state_commitment_tree_height: u64,
    pub(crate) sequencer_address: Address,
    pub(crate) cairo_resource_fee_weights: HashMap<String, f64>,
    #[get_copy = "pub"]
    pub(crate) invoke_tx_max_n_steps: u64,
    pub(crate) validate_max_n_steps: u64,
    #[get_mut = "pub"]
    pub(crate) block_info: BlockInfo,
}

impl StarknetGeneralConfig {
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub(crate) fn new(
        starknet_os_config: StarknetOsConfig,
        contract_storage_commitment_tree_height: u64,
        global_state_commitment_tree_height: u64,
        invoke_tx_max_n_steps: u64,
        block_info: BlockInfo,
    ) -> Self {
        Self {
            starknet_os_config,
            contract_storage_commitment_tree_height: contract_storage_commitment_tree_height,
            global_state_commitment_tree_height: global_state_commitment_tree_height,
            sequencer_address: sequencer_address,
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
            contract_storage_commitment_tree_height: 0,
            global_state_commitment_tree_height: 0,
            sequencer_address: Address(0.into()),
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
