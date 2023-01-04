use std::collections::HashMap;
use num_bigint::BigInt;
use patricia_tree::PatriciaTree;
use crate::starknet_storage::storage::{FactFetchingContext, Storage};
use crate::starknet_storage::dict_storage::DictStorage;
use crate::starknet_storage::storage_leaf::StorageLeaf;


const UNINITIALIZED_CLASS_HASH: &[u8; 32] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

/// An immutable Patricia-Merkle tree backed by an immutable fact storage.
pub struct StarknetPatriciaTree {
    inner: PatriciaTree<Vec<u8>>,
    ffc: FactFetchingContext<DictStorage>,
    height: u64,
    root: Vec<u8>,
}

impl StarknetPatriciaTree { 

}
/// Represents the state of a single contract (sub-commitment tree) 
/// in the full StarkNet state commitment tree.
/// The contract state contains the contract object 
/// (None if the contract was not yet deployed) and the commitment tree 
/// root of the contract storage.
#[derive(Debug, PartialEq)]
struct ContractState<K> {
    contract_hash: Vec<u8>,
    storage_commitment_tree: PatriciaTree<K>,
    nonce: u64
}

impl<K> ContractState<K> {
    pub fn new(contract_hash: Vec<u8>, storage_commitment_tree: PatriciaTree<K>, nonce: u64) -> Self {
        Self {
            contract_hash,
            storage_commitment_tree,
            nonce,
        }
    }

    pub fn empty<T: Storage>(storage_commitment_tree_height: u64, ffc: FactFetchingContext<T>) -> Self {
        let empty_tree = todo!();
        Self {
            contract_hash: UNINITIALIZED_CLASS_HASH.to_vec(),
            storage_commitment_tree: empty_tree,
            nonce: 0,
        }
    }


    pub fn is_empty(&self) -> bool {
        !self.is_initialized()
    }

    /// Returns true if the contract state is initialized, this is
    /// when it has a contract_hash different from the default one.
    pub fn is_initialized(&self) -> bool {
        let uninitialized = self.contract_hash == UNINITIALIZED_CLASS_HASH;

        // TODO add the assert and return a Result<bool, Error>
        !uninitialized
    }
    
    /// Computes the hash of the node containing the contract's information,
    /// including the contract definition and storage.
    fn hash(&self) -> &[u8] {
        if self.is_empty() {
            return todo!() 
        }

        let contract_state_hash_version = 0;

        // set hash_value = H(H(contract_hash, storage_root), RESERVED).
        let mut hash_value = todo!();
        //hash_value = hash_func(hash_value, to_bytes(self.nonce))
        hash_value = todo!();

        /// Return H(hash_value, CONTRACT_STATE_HASH_VERSION). 
        /// CONTRACT_STATE_HASH_VERSION must be in the outermost hash 
        /// to guarantee unique "decoding".
        // return hash_func(hash_value, to_bytes(CONTRACT_STATE_HASH_VERSION))
        todo!()
    }

/// Returns a new ContractState object with the same contract object and 
/// a newly calculated root, according to the given updates of its leaves.
/// In a case of an empty contract - it is possible to update the class 
/// hash as well.
    pub fn update<T: Storage>(&mut self, ffc: FactFetchingContext<T>, updates: HashMap<u64, StorageLeaf>, nonce: Option<u64>, class_hash: Option<Vec<u8>>) -> Self {
        let cls_hash = match class_hash {
            Some(cls) => cls,
            None => self.contract_hash,
        };

        let nonce_used = match nonce {
            Some(n) => n,
            None => self.nonce,
        };

        let updated_storage_commitment_tree = self.storage_commitment_tree.update(ffc, updates.items());

        // TODO: add validation 

        ContractState { 
            contract_hash: cls_hash,
            storage_commitment_tree: updated_storage_commitment_tree,
            nonce: nonce_used
        }
    }
}


/// A Patricia implementation of StateReader.
#[derive(Debug, PartialEq)]
struct PatriciaStateReader<T, S1: Storage, S2: Storage> {
    /// The last committed state; the one this state was created from.
    global_state_root: PatriciaTree<T>,
    /// Fact fetching context used for retrieving facts.
    ffc: FactFetchingContext<S1>,
    /// Stored contract classes.
    contract_class_storage: S2,
    /// A mapping from contract address to its cached state.
    contract_states: HashMap<u64, ContractState<S1>>,
}
