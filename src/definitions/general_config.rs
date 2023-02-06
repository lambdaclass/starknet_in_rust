use felt::Felt;
use num_traits::{Num, Zero};

use crate::utils::Address;

use super::errors::general_config_error::StarknetChainIdError;

#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum StarknetChainId {
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

impl Default for StarknetChainId {
    fn default() -> Self {
        StarknetChainId::TestNet
    }
}

impl StarknetChainId {
    pub(crate) fn to_felt(self) -> Felt {
        Felt::from_bytes_be(self.to_string().as_bytes())
    }

    pub(crate) fn as_u64(&self) -> Result<u64, StarknetChainIdError> {
        let id = self.to_string().as_bytes().to_vec();

        if id.len() == 8 {
            let bytes: [u8; 8] = id
                .try_into()
                .map_err(|_| StarknetChainIdError::ConversionErrorToBytes)?;

            Ok(u64::from_ne_bytes(bytes))
        } else if id.len() < 8 {
            id.resize_with(8, || 0);
            let bytes = id
                .try_into()
                .map_err(|_| StarknetChainIdError::ConversionErrorToBytes)?;
            Ok(u64::from_ne_bytes(bytes))
        } else {
            Err(StarknetChainIdError::ConversionErrorToBytes)
        }
    }
}

#[allow(unused)]
#[derive(Debug, Clone, Default)]
pub(crate) struct StarknetOsConfig {
    pub(crate) chain_id: StarknetChainId,
    pub(crate) fee_token_address: Address,
}

#[allow(unused)]
#[derive(Debug, Clone, Default)]
pub struct StarknetGeneralConfig {
    pub(crate) starknet_os_config: StarknetOsConfig,
    contract_storage_commitment_tree_height: u64,
    global_state_commitment_tree_height: u64,
    pub(crate) sequencer_address: Address,
    pub(crate) invoke_tx_max_n_steps: u64,
}

impl StarknetGeneralConfig {
    pub(crate) fn new(
        starknet_os_config: StarknetOsConfig,
        contract_storage_commitment_tree_height: u64,
        global_state_commitment_tree_height: u64,
        sequencer_address: Address,
        invoke_tx_max_n_steps: u64,
    ) -> Self {
        Self {
            starknet_os_config,
            contract_storage_commitment_tree_height,
            global_state_commitment_tree_height,
            sequencer_address,
            invoke_tx_max_n_steps,
        }
    }
    pub(crate) fn default() -> Self {
        Self {
            starknet_os_config: StarknetOsConfig {
                chain_id: StarknetChainId::TestNet,
                fee_token_address: Address(Felt::zero()),
            },
            contract_storage_commitment_tree_height: 0,
            global_state_commitment_tree_height: 0,
            sequencer_address: Address(0.into()),
            invoke_tx_max_n_steps: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use felt::felt_str;

    use super::*;

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
