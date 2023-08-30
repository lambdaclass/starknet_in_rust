use crate::{services::api::contract_classes::compiled_class::CompiledClass, utils::ClassHash};
use std::collections::HashMap;

pub trait ContractClassCache {
    fn get_contract_class(&self, class_hash: ClassHash) -> Option<CompiledClass>;
    fn set_contract_class(&mut self, class_hash: ClassHash, compiled_class: CompiledClass);

    fn merge_with<I>(&mut self, other: I)
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

#[derive(Clone, Copy, Debug, Default, Hash)]
pub struct NullContractClassCache;

impl ContractClassCache for NullContractClassCache {
    fn get_contract_class(&self, _class_hash: ClassHash) -> Option<CompiledClass> {
        None
    }

    fn set_contract_class(&mut self, _class_hash: ClassHash, _compiled_class: CompiledClass) {
        // Nothing needs to be done here.
    }

    fn merge_with<I>(&mut self, _other: I)
    where
        I: IntoIterator<Item = (ClassHash, CompiledClass)>,
    {
        // Nothing needs to be done here.
    }
}

#[derive(Clone, Debug, Default)]
pub struct PermanentContractClassCache {
    storage: HashMap<ClassHash, CompiledClass>,
}

impl ContractClassCache for PermanentContractClassCache {
    fn get_contract_class(&self, class_hash: ClassHash) -> Option<CompiledClass> {
        self.storage.get(&class_hash).cloned()
    }

    fn set_contract_class(&mut self, class_hash: ClassHash, compiled_class: CompiledClass) {
        self.storage.insert(class_hash, compiled_class);
    }

    fn merge_with<I>(&mut self, other: I)
    where
        I: IntoIterator<Item = (ClassHash, CompiledClass)>,
    {
        self.storage.extend(other);
    }
}

impl IntoIterator for PermanentContractClassCache {
    type Item = (ClassHash, CompiledClass);
    type IntoIter = <HashMap<ClassHash, CompiledClass> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.storage.into_iter()
    }
}

impl IntoIterator for &PermanentContractClassCache {
    type Item = (ClassHash, CompiledClass);
    type IntoIter = <HashMap<ClassHash, CompiledClass> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.storage.clone().into_iter()
    }
}
