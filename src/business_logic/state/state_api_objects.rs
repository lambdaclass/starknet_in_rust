use crate::{starkware_utils::starkware_errors::StarkwareError, utils::Address};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    /// The sequence number of the last block created.
    pub block_number: u64,
    /// Timestamp of the beginning of the last block creation attempt.
    pub block_timestamp: u64,
    /// L1 gas price (in Wei) measured at the beginning of the last block creation attempt.
    pub gas_price: u64,
    /// The sequencer address of this block.
    pub sequencer_address: Address,
    /// The version of StarkNet system (e.g. "0.10.3").
    pub starknet_version: String,
}

impl BlockInfo {
    pub fn empty(sequencer_address: Address) -> Self {
        BlockInfo {
            block_number: 0, // To do: In cairo-lang, this value is set to -1
            block_timestamp: 0,
            gas_price: 0,
            sequencer_address,
            starknet_version: "0.0.0".to_string(),
        }
    }

    pub fn validate_legal_progress(
        &self,
        next_block_info: &BlockInfo,
    ) -> Result<(), StarkwareError> {
        if self.block_number + 1 != next_block_info.block_number {
            return Err(StarkwareError::InvalidBlockNumber);
        }

        if self.block_timestamp >= next_block_info.block_timestamp {
            return Err(StarkwareError::InvalidBlockTimestamp);
        }

        Ok(())
    }
}

impl Default for BlockInfo {
    fn default() -> Self {
        Self {
            block_number: 0,
            block_timestamp: 0,
            gas_price: 0,
            sequencer_address: Address(0.into()),
            starknet_version: "0.0.0".to_string(),
        }
    }
}

#[test]
fn test_validate_legal_progress() {
    let first_block = BlockInfo::default();
    let next_block: BlockInfo = BlockInfo {
        block_number: 1,
        block_timestamp: 1,
        ..Default::default()
    };

    assert!(first_block.validate_legal_progress(&next_block).is_ok())
}
