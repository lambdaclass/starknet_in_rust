use num_bigint::BigInt;

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

#[allow(unused)]
#[derive(Debug, Clone)]
pub(crate) struct StarknetOsConfig {
    pub(crate) chain_id: StarknetChainId,
    pub(crate) fee_token_address: BigInt,
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub(crate) struct StarknetGeneralConfig {
    pub(crate) starknet_os_config: StarknetOsConfig,
}

impl StarknetGeneralConfig {
    pub(crate) fn new() -> Self {
        todo!()
    }
}
