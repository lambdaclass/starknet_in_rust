//! # Contract cache system
//!
//! The contract caches allow the application to keep some contracts within itself, providing them
//! efficiently when they are needed.
//!
//! The trait `ContractClassCache` provides methods for retrieving and inserting elements into the
//! cache. It also contains a method to extend the shared cache from an iterator so that it can be
//! used with the private caches.

use crate::{
    services::api::contract_classes::compiled_class::CompiledClass, transaction::ClassHash,
};
use std::{collections::HashMap, sync::RwLock};

/// The contract class cache trait, which must be implemented by all caches.
pub trait ContractClassCache {
    /// Provides the stored contract class associated with a specific class hash, or `None` if not
    /// present.
    fn get_contract_class(&self, class_hash: ClassHash) -> Option<CompiledClass>;
    /// Inserts or replaces a contract class associated with a specific class hash.
    fn set_contract_class(&self, class_hash: ClassHash, compiled_class: CompiledClass);
}

/// A contract class cache which stores nothing. In other words, using this as a cache means there's
/// effectively no cache.
#[derive(Clone, Copy, Debug, Default, Hash)]
pub struct NullContractClassCache;

impl ContractClassCache for NullContractClassCache {
    fn get_contract_class(&self, _class_hash: ClassHash) -> Option<CompiledClass> {
        None
    }

    fn set_contract_class(&self, _class_hash: ClassHash, _compiled_class: CompiledClass) {
        // Nothing needs to be done here.
    }
}

/// A contract class cache which stores everything. This cache is useful for testing but will
/// probably end up taking all the memory available if the application is long running.
#[derive(Debug, Default)]
pub struct PermanentContractClassCache {
    storage: RwLock<HashMap<ClassHash, CompiledClass>>,
}

impl PermanentContractClassCache {
    pub fn extend<I>(&self, other: I)
    where
        I: IntoIterator<Item = (ClassHash, CompiledClass)>,
    {
        self.storage.write().unwrap().extend(other);
    }
}

impl ContractClassCache for PermanentContractClassCache {
    fn get_contract_class(&self, class_hash: ClassHash) -> Option<CompiledClass> {
        self.storage.read().unwrap().get(&class_hash).cloned()
    }

    fn set_contract_class(&self, class_hash: ClassHash, compiled_class: CompiledClass) {
        self.storage
            .write()
            .unwrap()
            .insert(class_hash, compiled_class);
    }
}

impl Clone for PermanentContractClassCache {
    fn clone(&self) -> Self {
        Self {
            storage: RwLock::new(self.storage.read().unwrap().clone()),
        }
    }
}

impl IntoIterator for PermanentContractClassCache {
    type Item = (ClassHash, CompiledClass);
    type IntoIter = <HashMap<ClassHash, CompiledClass> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.storage.into_inner().unwrap().into_iter()
    }
}

impl IntoIterator for &PermanentContractClassCache {
    type Item = (ClassHash, CompiledClass);
    type IntoIter = <HashMap<ClassHash, CompiledClass> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.storage.read().unwrap().clone().into_iter()
    }
}
