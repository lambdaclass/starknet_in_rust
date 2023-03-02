use felt::Felt;
use num_traits::ToPrimitive;
use sha3::{Digest, Keccak256};

use crate::utils::Address;

/// A StarkNet Message from L2 to L1.
#[derive(Debug, Clone)]
pub(crate) struct StarknetMessageToL1 {
    from_address: Address,
    to_address: Address,
    payload: Vec<Felt>,
}

impl StarknetMessageToL1 {
    pub fn new(from_address: Address, to_address: Address, payload: Vec<Felt>) -> Self {
        StarknetMessageToL1 {
            from_address,
            to_address,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<Felt> {
        let mut encoding = Vec::with_capacity(self.payload.len() + 3);
        encoding.push(self.from_address.0.clone());
        encoding.push(self.to_address.0.clone());
        encoding.push(self.payload.len().into());
        encoding.append(&mut self.payload.clone());

        encoding
    }

    pub fn get_hash(&self) -> Vec<u8> {
        let data = self
            .encode()
            .iter()
            .map(|elem| elem.to_usize().unwrap() as u8)
            .collect::<Vec<u8>>();
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let finalized_hash = hasher.finalize();
        finalized_hash.as_slice().to_vec()
    }
}
