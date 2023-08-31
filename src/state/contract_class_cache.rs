//! # Contract cache system
//!
//! The contract caches allow the application to keep some contracts within itself, providing them
//! efficiently when they are needed.
//!
//! The trait `ContractClassCache` provides methods for retrieving and inserting elements into the
//! cache. It also contains a method to extend the shared cache from an iterator so that it can be
//! used with the private caches.
//!
//! TODO: Right now, it's impossible to implement the issue's `merge_caches` because
//!   `ContractClassCache::extend` will be called already with the write lock in place. To solve
//!   this, the lock may be pushed into the cache, but the methods will not be able to have
//!   `&mut self` as the object.

use crate::{services::api::contract_classes::compiled_class::CompiledClass, utils::ClassHash};
use std::{collections::HashMap, sync::RwLock};

/// The contract class cache trait, which must be implemented by all caches.
pub trait ContractClassCache {
    /// Provides the stored contract class associated with a specific class hash, or `None` if not
    /// present.
    fn get_contract_class(&self, class_hash: ClassHash) -> Option<CompiledClass>;
    /// Inserts or replaces a contract class associated with a specific class hash.
    fn set_contract_class(&self, class_hash: ClassHash, compiled_class: CompiledClass);

    /// Performs a bulk insert of contract classes from an iterator over pairs of the class hash and
    /// its contract class.
    fn extend<I>(&self, other: I)
    where
        I: IntoIterator<Item = (ClassHash, CompiledClass)>;
}

// pub(crate) fn merge_caches(
//     shared: &RwLock<HashMap<ClassHash, CompiledClass>>,
//     mut private: HashMap<ClassHash, CompiledClass>,
// ) {
//     // FIXME: Parallel invocation of `merge_caches()` may cause data loss. Example:
//     //   - Thread A: Invokes `merge_caches()`. Starts copying data from `shared` into its `private`.
//     //   - Thread B: Invokes `merge_caches()`. Starts copying data from `shared` into its `private`.
//     //   - Thread A: Updates the shared cache. It now contains A's specific entries.
//     //   - Thread B: Updates the shared cache. It now contains only B's specific entries, since it
//     //     lost A's ones.

//     // Extend private to contain all of shared's entries. Using a readonly lock will avoid blocking
//     // the other potential cache readers.
//     {
//         let shared_lock = shared.read().unwrap();
//         private.extend(shared_lock.iter().map(|(k, v)| (*k, v.clone())));
//     }

//     // Swap the active cache to apply the changes. This will delay `private`'s destructor, which
//     // will run after the write lock has been dropped.
//     {
//         let mut shared_lock = shared.write().unwrap();
//         mem::swap(&mut *shared_lock, &mut private);
//     }
// }

// pub(crate) fn take_cache<T, C>(state: CachedState<T, C>) -> HashMap<ClassHash, CompiledClass>
// where
//     T: StateReader,
//     C: ContractClassCache,
// {
//     state.contract_class_cache_private
// }

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

    fn extend<I>(&self, _other: I)
    where
        I: IntoIterator<Item = (ClassHash, CompiledClass)>,
    {
        // Nothing needs to be done here.
    }
}

/// A contract class cache which stores everything. This cache is useful for testing but will
/// probably end up taking all the memory available if the application is long running.
#[derive(Debug, Default)]
pub struct PermanentContractClassCache {
    storage: RwLock<HashMap<ClassHash, CompiledClass>>,
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

    fn extend<I>(&self, other: I)
    where
        I: IntoIterator<Item = (ClassHash, CompiledClass)>,
    {
        self.storage.write().unwrap().extend(other);
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
