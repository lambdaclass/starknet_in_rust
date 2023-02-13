use crate::utils::Address;
use felt::Felt;
use getset::CopyGetters;
use num_traits::{Num, Zero};

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

impl StarknetChainId {
    pub(crate) fn to_felt(self) -> Felt {
        Felt::from_bytes_be(self.to_string().as_bytes())
    }
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub(crate) struct StarknetOsConfig {
    pub(crate) chain_id: StarknetChainId,
    pub(crate) fee_token_address: Address,
}

#[allow(unused)]
#[derive(Clone, Debug, CopyGetters)]
pub struct StarknetGeneralConfig {
    pub(crate) starknet_os_config: StarknetOsConfig,
    contract_storage_commitment_tree_height: u64,
    global_state_commitment_tree_height: u64,
    sequencer_address: Address,
    #[get_copy = "pub"]
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
}

impl Default for StarknetGeneralConfig {
    fn default() -> Self {
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
