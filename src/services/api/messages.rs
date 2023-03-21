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
        encoding.extend_from_slice(&self.payload);

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

#[test]
fn create_starknet_message_to_l1() {
    let from_address: Address = Address(42.into());
    let to_address: Address = Address(1729.into());
    let payload: Vec<Felt> = Vec::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]);
    let message = StarknetMessageToL1::new(from_address, to_address, payload);

    assert_eq!(message.from_address, Address(42.into()));
    assert_eq!(message.to_address, Address(1729.into()));
    assert_eq!(
        message.payload,
        Vec::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4),])
    )
}

#[test]
fn encode_starknet_message_to_l1() {
    let message = StarknetMessageToL1::new(
        Address(42.into()),
        Address(1729.into()),
        Vec::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)]),
    );

    let expected_output = Vec::from([
        Felt::new(42),
        Felt::new(1729),
        Felt::new(4),
        Felt::new(1),
        Felt::new(2),
        Felt::new(3),
        Felt::new(4),
    ]);

    assert_eq!(message.encode(), expected_output);
}
