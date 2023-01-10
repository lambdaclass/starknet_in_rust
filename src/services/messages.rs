use std::vec;

use cairo_rs::bigint;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use sha3::{Digest, Keccak256};
use std::str;

#[derive(Clone)]
pub(crate) struct StarknetMessageToL1 {
    from_address: usize,
    to_address: usize,
    payload: Vec<BigInt>,
}

impl StarknetMessageToL1 {
    pub fn new(from_address: usize, to_address: usize, payload: Vec<BigInt>) -> Self {
        StarknetMessageToL1 {
            from_address,
            to_address,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<BigInt> {
        let from_address = bigint!(self.from_address);
        let to_address = bigint!(self.to_address);
        let payload_size = bigint!(self.payload.len());
        let mut data = self.payload.clone();
        let mut encode = Vec::with_capacity(self.payload.len() + 3);
        encode.push(from_address);
        encode.push(to_address);
        encode.push(payload_size);
        encode.append(&mut data);
        encode
    }

    pub fn get_hash(&self) -> String {
        todo!()
    }
}
