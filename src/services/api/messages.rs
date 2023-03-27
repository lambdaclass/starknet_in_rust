use felt::Felt252;
use num_traits::ToPrimitive;
use sha3::{Digest, Keccak256};

use crate::utils::Address;

/// A StarkNet Message from L2 to L1.
#[derive(Debug, Clone)]
pub(crate) struct StarknetMessageToL1 {
    from_address: Address,
    to_address: Address,
    payload: Vec<Felt252>,
}

impl StarknetMessageToL1 {
    pub fn new(from_address: Address, to_address: Address, payload: Vec<Felt252>) -> Self {
        StarknetMessageToL1 {
            from_address,
            to_address,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<Felt252> {
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
    let from_address = Address(42.into());
    let to_address = Address(1729.into());
    let payload: Vec<Felt252> = vec![1.into(), 2.into(), 3.into(), 4.into()];
    let message = StarknetMessageToL1::new(from_address, to_address, payload);

    assert_eq!(message.from_address, Address(42.into()));
    assert_eq!(message.to_address, Address(1729.into()));
    assert_eq!(
        message.payload,
        vec![1.into(), 2.into(), 3.into(), 4.into()]
    )
}

#[test]
fn encode_starknet_message_to_l1() {
    let message = StarknetMessageToL1::new(
        Address(42.into()),
        Address(1729.into()),
        vec![1.into(), 2.into(), 3.into(), 4.into()],
    );

    let expected_output = vec![
        42.into(),
        1729.into(),
        4.into(),
        1.into(),
        2.into(),
        3.into(),
        4.into(),
    ];

    assert_eq!(message.encode(), expected_output);
}

#[test]
fn get_hash_for_starknet_message_to_l1() {
    let message = StarknetMessageToL1::new(
        Address(42.into()),
        Address(1729.into()),
        vec![1.into(), 2.into(), 3.into(), 4.into()],
    );

    assert_eq!(
        message.get_hash(),
        Vec::from([
            35, 146, 105, 229, 123, 197, 150, 164, 71, 161, 100, 157, 18, 54, 233, 219, 32, 150,
            155, 238, 74, 8, 254, 114, 153, 144, 74, 32, 110, 104, 86, 42
        ])
    )
}
