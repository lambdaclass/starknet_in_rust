#[derive(Debug, Clone, PartialEq)]
pub struct BlockInfo {
    // The sequence number of the last block created.
    pub(crate) block_number: u64,

    // Timestamp of the beginning of the last block creation attempt.
    pub(crate) block_timestamp: u64,

    // L1 gas price (in Wei) measured at the beginning of the last block creation attempt.
    gas_price: u64,

    // The sequencer address of this block.
    pub(crate) sequencer_address: u64,

    // The version of StarkNet system (e.g. "0.10.3").
    starknet_version: String,
}

impl Default for BlockInfo {
    fn default() -> Self {
        Self {
            block_number: 0,
            block_timestamp: 0,
            gas_price: 0,
            sequencer_address: 0,
            starknet_version: "0.0.0".to_string(),
        }
    }
}
