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

    pub fn encode(&self) -> Vec<usize> {
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
            .iter()
            .map(|x| x.to_usize().unwrap())
            .collect::<Vec<usize>>()
    }

    // pub fn get_hash(&self) -> String {
    //     let mut hasher = Keccak256::new();
    //     hasher.update(&self.encode());

    //     let hashed = hasher.finalize();
    //     String::from(str::from_utf8(&hashed).unwrap())
    // }
}

// #[cfg(test)]
// mod test {
//     use num_bigint::{BigInt, Sign};
//     use crate::bigint;

//     use super::StarknetMessageToL1;

//     #[test]
//     fn keccak() {
//         let msg = StarknetMessageToL1::new(123, 321, vec![bigint!(1)]);
//         assert_eq!(msg.get_hash(), "asdasd");
//     }
// }
