use num_bigint::BigInt;


/// A class representing a commitment tree leaf in a Cairo contract storage.
/// The content of the leaf is a single integer.
pub struct StorageLeaf {
    value: BigInt
}

impl StorageLeaf {
    pub fn empty() -> Self {
        Self {
            value: 0.into()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.value == 0.into()
    }

    pub fn prefix() -> Vec<u8> {
        b"starknet_storage_leaf".to_vec()
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.value.to_bytes_be().1.to_vec()
    }

    /// Calculates and returns the leaf hash.
    /// Note that the return value size needs to be HASH_BYTES.
    pub fn hash(&self) -> Vec<u8> {
        if self.is_empty() {
            // EMPTY_NODE_HASH
            todo!()
        } else {
            self.serialize()
        }
    }

    pub fn deserialize(data: Vec<u8>) -> Self {
        Self { 
            // value: from_bytes(data)
            value: todo!()
        }
    }




}
