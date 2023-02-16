use std::collections::HashMap;

use crate::utils::Address;
use felt::Felt;
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

    pub(crate) fn as_u64(&self) -> Result<u64, StarknetChainIdError> {
        let mut id = self.to_string().as_bytes().to_vec();

        match id.len() {
            (0..=7) | 8 => {
                id.resize_with(8, || 0);
                let bytes = id
                    .try_into()
                    .map_err(|_| StarknetChainIdError::ConversionErrorToBytes)?;
                Ok(u64::from_ne_bytes(bytes))
            }
            _ => Err(StarknetChainIdError::ConversionErrorToBytes),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StarknetOsConfig {
    pub(crate) chain_id: StarknetChainId,
    pub(crate) fee_token_address: Address,
    pub(crate) gas_price: u64,
}

#[derive(Debug, Clone)]
pub struct StarknetGeneralConfig {
    pub(crate) starknet_os_config: StarknetOsConfig,
    pub(crate) contract_storage_commitment_tree_height: u64,
    global_state_commitment_tree_height: u64,
    pub(crate) sequencer_address: Address,
    pub(crate) cairo_resource_fee_weights: HashMap<String, f64>,
    pub(crate) invoke_tx_max_n_steps: u64,
    pub(crate) validate_max_n_steps: u64,
}

impl StarknetGeneralConfig {
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub(crate) fn new(
        starknet_os_config: StarknetOsConfig,
        contract_storage_commitment_tree_height: u64,
        global_state_commitment_tree_height: u64,
        sequencer_address: Address,
        invoke_tx_max_n_steps: u64,
    ) -> Self {
        Self {
            starknet_os_config,
            contract_storage_commitment_tree_height: contract_storage_commitment_tree_height,
            global_state_commitment_tree_height: global_state_commitment_tree_height,
            sequencer_address: sequencer_address,
            invoke_tx_max_n_steps,
            cairo_resource_fee_weights: HashMap::new(),
            validate_max_n_steps: 0,
        }
    }

    pub(crate) fn default() -> Self {
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
