//! # Starknet Block Context
//!
//! This module contains structs representing the context of a specific Starknet block.

use crate::{state::BlockInfo, utils::Address};
use cairo_vm::felt::Felt252;
use core::fmt;
use getset::{CopyGetters, Getters, MutGetters};
use starknet_api::block::Block;
use std::collections::HashMap;

use super::constants::{
    DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS, DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
    DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT, DEFAULT_INVOKE_TX_MAX_N_STEPS,
    DEFAULT_SEQUENCER_ADDRESS, DEFAULT_STARKNET_OS_CONFIG, DEFAULT_VALIDATE_MAX_N_STEPS,
};

/// Unique identifier of a Starknet chain.
#[derive(Debug, Clone, Copy)]
pub enum StarknetChainId {
    /// Starknet main chain
    MainNet,
    /// Starknet first test chain (Goerli)
    TestNet,
    /// Starknet second test chain (Goerli 2)
    TestNet2,
}

impl fmt::Display for StarknetChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StarknetChainId::MainNet => write!(f, "SN_MAIN"),
            StarknetChainId::TestNet => write!(f, "SN_GOERLI"),
            StarknetChainId::TestNet2 => write!(f, "SN_GOERLI2"),
        }
    }
}

impl StarknetChainId {
    /// Returns the chain ID's representation as a field element.
    ///
    /// # Examples
    ///
    /// ```
    /// use starknet_in_rust::definitions::block_context::StarknetChainId;
    /// use starknet_in_rust::felt::felt_str;
    ///
    /// assert_eq!(
    ///     StarknetChainId::MainNet.to_felt(),
    ///     felt_str!("23448594291968334"),
    /// );
    /// assert_eq!(
    ///    StarknetChainId::TestNet.to_felt(),
    ///    felt_str!("1536727068981429685321"),
    /// );
    /// assert_eq!(
    ///     StarknetChainId::TestNet2.to_felt(),
    ///     felt_str!("393402129659245999442226"),
    /// );
    /// ```
    pub fn to_felt(self) -> Felt252 {
        Felt252::from_bytes_be(self.to_string().as_bytes())
    }
}

#[derive(Debug, Clone, Getters, MutGetters)]
/// Starknet OS configuration.
pub struct StarknetOsConfig {
    /// ID of the configured chain
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) chain_id: Felt252,
    /// Address of the token used when paying fees
    #[get = "pub"]
    pub(crate) fee_token_address: Address,
    /// Price of gas
    pub(crate) gas_price: u128,
}

impl StarknetOsConfig {
    /// Creates a new [`StarknetOsConfig`].
    ///
    /// # Arguments
    ///
    /// * `chain_id` - [`Felt252`] of the configured chain.
    /// * `fee_token_address` - Address of the token used when paying fees.
    /// * `gas_price` - Price of gas.
    pub fn new(chain_id: Felt252, fee_token_address: Address, gas_price: u128) -> Self {
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

/// Starknet block context.
#[derive(Clone, Debug, CopyGetters, Getters, MutGetters)]
pub struct BlockContext {
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
    /// Contains the blocks in the range [ current_block - 1024, current_block - 10 ]
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) blocks: HashMap<u64, Block>,
    pub(crate) enforce_l1_handler_fee: bool,
}

impl BlockContext {
    /// Creates a new [`BlockContext`].
    ///
    /// # Arguments
    ///
    /// * `starknet_os_config` - Starknet OS configuration.
    /// * `contract_storage_commitment_tree_height` - Height of the contract storage commitment tree.
    /// * `global_state_commitment_tree_height` - Height of the global state commitment tree.
    /// * `cairo_resource_fee_weights` - Weights used when calculating transaction fees.
    /// * `invoke_tx_max_n_steps` - Maximum number of steps allowed when executing transactions.
    /// * `validate_max_n_steps` - Maximum number of steps allowed when validating transactions.
    /// * `block_info` - Information about the current block.
    /// * `blocks` - Blocks in the range [ current_block - 1024, current_block - 10 ].
    ///     Example: for block number 6351, this includes the blocks 5327, 5328, ..., 6340, 6341.
    /// * `enforce_l1_handler_fee` - Whether to enforce the L1 handler fee.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        starknet_os_config: StarknetOsConfig,
        contract_storage_commitment_tree_height: u64,
        global_state_commitment_tree_height: u64,
        cairo_resource_fee_weights: HashMap<String, f64>,
        invoke_tx_max_n_steps: u64,
        validate_max_n_steps: u64,
        block_info: BlockInfo,
        blocks: HashMap<u64, Block>,
        enforce_l1_handler_fee: bool,
    ) -> Self {
        Self {
            starknet_os_config,
            contract_storage_commitment_tree_height,
            global_state_commitment_tree_height,
            invoke_tx_max_n_steps,
            cairo_resource_fee_weights,
            validate_max_n_steps,
            block_info,
            blocks,
            enforce_l1_handler_fee,
        }
    }
}

impl Default for BlockContext {
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
            blocks: HashMap::default(),
            enforce_l1_handler_fee: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_vm::felt::felt_str;
    use coverage_helper::test;

    #[test]
    fn starknet_chain_to_felt() {
        assert_eq!(
            StarknetChainId::MainNet.to_felt(),
            felt_str!("23448594291968334"),
        );
        assert_eq!(
            StarknetChainId::TestNet.to_felt(),
            felt_str!("1536727068981429685321"),
        );
        assert_eq!(
            StarknetChainId::TestNet2.to_felt(),
            felt_str!("393402129659245999442226"),
        );
    }
}
