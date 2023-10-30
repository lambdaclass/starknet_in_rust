use super::{
    contract_class_cache::ContractClassCache,
    state_api::{State, StateChangesCount, StateReader},
    state_cache::{StateCache, StorageEntry},
};
use crate::{
    core::errors::state_errors::StateError,
    services::api::contract_classes::compiled_class::CompiledClass,
    state::StateDiff,
    utils::{
        get_erc20_balance_var_addresses, subtract_mappings, subtract_mappings_keys,
        to_cache_state_storage_mapping, Address, ClassHash,
    },
};
use cairo_lang_utils::bigint::BigUintAsHex;
use cairo_vm::felt::Felt252;
use getset::{Getters, MutGetters};
use num_traits::Zero;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

pub const UNINITIALIZED_CLASS_HASH: &ClassHash = &[0u8; 32];

/// Represents a cached state of contract classes with optional caches.
#[derive(Default, Debug, Getters, MutGetters)]
pub struct CachedState<T: StateReader, C: ContractClassCache> {
    pub state_reader: Arc<T>,
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) cache: StateCache,

    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) contract_class_cache: Arc<C>,
    pub(crate) contract_class_cache_private: RwLock<HashMap<ClassHash, CompiledClass>>,

    #[cfg(feature = "metrics")]
    cache_hits: usize,
    #[cfg(feature = "metrics")]
    cache_misses: usize,
}

#[cfg(feature = "metrics")]
impl<T: StateReader, C: ContractClassCache> CachedState<T, C> {
    #[inline(always)]
    pub fn add_hit(&mut self) {
        self.cache_hits += 1;
    }

    #[inline(always)]
    pub fn add_miss(&mut self) {
        self.cache_misses += 1;
    }
}

#[cfg(not(feature = "metrics"))]
impl<T: StateReader, C: ContractClassCache> CachedState<T, C> {
    #[inline(always)]
    pub fn add_hit(&mut self) {
        // does nothing
    }

    #[inline(always)]
    pub fn add_miss(&mut self) {
        // does nothing
    }
}

impl<T: StateReader, C: ContractClassCache> CachedState<T, C> {
    /// Constructor, creates a new cached state.
    pub fn new(state_reader: Arc<T>, contract_classes: Arc<C>) -> Self {
        Self {
            cache: StateCache::default(),
            state_reader,
            contract_class_cache: contract_classes,
            contract_class_cache_private: RwLock::new(HashMap::new()),

            #[cfg(feature = "metrics")]
            cache_hits: 0,
            #[cfg(feature = "metrics")]
            cache_misses: 0,
        }
    }

    /// Creates a CachedState for testing purposes.
    pub fn new_for_testing(
        state_reader: Arc<T>,
        cache: StateCache,
        contract_classes: Arc<C>,
    ) -> Self {
        Self {
            cache,
            state_reader,
            contract_class_cache: contract_classes,
            contract_class_cache_private: RwLock::new(HashMap::new()),

            #[cfg(feature = "metrics")]
            cache_hits: 0,
            #[cfg(feature = "metrics")]
            cache_misses: 0,
        }
    }

    /// Clones a CachedState for testing purposes.
    pub fn clone_for_testing(&self) -> Self {
        Self {
            state_reader: self.state_reader.clone(),
            cache: self.cache.clone(),
            contract_class_cache: self.contract_class_cache.clone(),
            contract_class_cache_private: RwLock::new(
                self.contract_class_cache_private.read().unwrap().clone(),
            ),
            #[cfg(feature = "metrics")]
            cache_hits: self.cache_hits,
            #[cfg(feature = "metrics")]
            cache_misses: self.cache_misses,
        }
    }

    pub fn drain_private_contract_class_cache(
        &self,
    ) -> Result<impl Iterator<Item = (ClassHash, CompiledClass)>, StateError> {
        Ok(self
            .contract_class_cache_private
            .read()
            .map_err(|_| StateError::FailedToReadContractClassCache)?
            .clone()
            .into_iter())
    }

    /// Creates a copy of this state with an empty cache for saving changes and applying them
    /// later.
    pub fn create_transactional(&self) -> Result<CachedState<T, C>, StateError> {
        Ok(CachedState {
            state_reader: self.state_reader.clone(),
            cache: self.cache.clone(),
            contract_class_cache: self.contract_class_cache.clone(),
            contract_class_cache_private: RwLock::new(
                self.contract_class_cache_private
                    .read()
                    .map_err(|_| StateError::FailedToReadContractClassCache)?
                    .clone(),
            ),
            #[cfg(feature = "metrics")]
            cache_hits: 0,
            #[cfg(feature = "metrics")]
            cache_misses: 0,
        })
    }
}

impl<T: StateReader, C: ContractClassCache> StateReader for CachedState<T, C> {
    /// Returns the class hash for a given contract address.
    /// Returns zero as default value if missing
    fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError> {
        self.cache
            .get_class_hash(contract_address)
            .map(|a| Ok(*a))
            .unwrap_or_else(|| self.state_reader.get_class_hash_at(contract_address))
    }

    /// Returns the nonce for a given contract address.
    fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError> {
        if self.cache.get_nonce(contract_address).is_none() {
            return self.state_reader.get_nonce_at(contract_address);
        }
        self.cache
            .get_nonce(contract_address)
            .ok_or_else(|| StateError::NoneNonce(contract_address.clone()))
            .cloned()
    }

    /// Returns storage data for a given storage entry.
    /// Returns zero as default value if missing
    fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
        self.cache
            .get_storage(storage_entry)
            .map(|v| Ok(v.clone()))
            .unwrap_or_else(|| self.state_reader.get_storage_at(storage_entry))
    }

    // TODO: check if that the proper way to store it (converting hash to address)
    /// Returned the compiled class hash for a given class hash.
    fn get_compiled_class_hash(&self, class_hash: &ClassHash) -> Result<ClassHash, StateError> {
        if let Some(compiled_class_hash) =
            self.cache.class_hash_to_compiled_class_hash.get(class_hash)
        {
            Ok(*compiled_class_hash)
        } else {
            self.state_reader.get_compiled_class_hash(class_hash)
        }
    }

    /// Returns the contract class for a given class hash.
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        // This method can receive both compiled_class_hash & class_hash and return both casm and deprecated contract classes
        //, which can be on the cache or on the state_reader, different cases will be described below:
        if class_hash == UNINITIALIZED_CLASS_HASH {
            return Err(StateError::UninitiaizedClassHash);
        }

        // I: FETCHING FROM CACHE
        let mut private_cache = self
            .contract_class_cache_private
            .write()
            .map_err(|_| StateError::FailedToReadContractClassCache)?;
        if let Some(compiled_class) = private_cache.get(class_hash) {
            return Ok(compiled_class.clone());
        } else if let Some(compiled_class) =
            self.contract_class_cache().get_contract_class(*class_hash)
        {
            private_cache.insert(*class_hash, compiled_class.clone());
            return Ok(compiled_class);
        }

        // I: CASM CONTRACT CLASS : CLASS_HASH
        if let Some(compiled_class_hash) =
            self.cache.class_hash_to_compiled_class_hash.get(class_hash)
        {
            if let Some(casm_class) = private_cache.get(compiled_class_hash) {
                return Ok(casm_class.clone());
            } else if let Some(casm_class) = self
                .contract_class_cache()
                .get_contract_class(*compiled_class_hash)
            {
                private_cache.insert(*class_hash, casm_class.clone());
                return Ok(casm_class);
            }
        }

        // II: FETCHING FROM STATE_READER
        let contract_class = self.state_reader.get_contract_class(class_hash)?;
        private_cache.insert(*class_hash, contract_class.clone());

        Ok(contract_class)
    }
}

impl<T: StateReader, C: ContractClassCache> State for CachedState<T, C> {
    /// Stores a contract class in the cache.
    fn set_contract_class(
        &mut self,
        class_hash: &ClassHash,
        contract_class: &CompiledClass,
    ) -> Result<(), StateError> {
        // `RefCell::get_mut()` provides a mutable reference without the borrowing overhead when we
        // have a mutable reference to the `RefCell` available.
        self.contract_class_cache_private
            .get_mut()
            .map_err(|_| StateError::FailedToReadContractClassCache)?
            .insert(*class_hash, contract_class.clone());

        Ok(())
    }

    /// Deploys a new contract and updates the cache.
    fn deploy_contract(
        &mut self,
        deploy_contract_address: Address,
        class_hash: ClassHash,
    ) -> Result<(), StateError> {
        if deploy_contract_address == Address(0.into()) {
            return Err(StateError::ContractAddressOutOfRangeAddress(
                deploy_contract_address.clone(),
            ));
        }

        match self.get_class_hash_at(&deploy_contract_address) {
            Ok(x) if x == [0; 32] => {}
            Ok(_) => {
                return Err(StateError::ContractAddressUnavailable(
                    deploy_contract_address.clone(),
                ))
            }
            _ => {}
        }

        self.cache
            .class_hash_writes
            .insert(deploy_contract_address.clone(), class_hash);
        Ok(())
    }

    fn increment_nonce(&mut self, contract_address: &Address) -> Result<(), StateError> {
        let new_nonce = self.get_nonce_at(contract_address)? + Felt252::from(1);
        self.cache
            .nonce_writes
            .insert(contract_address.clone(), new_nonce);
        Ok(())
    }

    fn set_storage_at(&mut self, storage_entry: &StorageEntry, value: Felt252) {
        self.cache
            .storage_writes
            .insert(storage_entry.clone(), value);
    }

    fn set_class_hash_at(
        &mut self,
        deploy_contract_address: Address,
        class_hash: ClassHash,
    ) -> Result<(), StateError> {
        if deploy_contract_address == Address(0.into()) {
            return Err(StateError::ContractAddressOutOfRangeAddress(
                deploy_contract_address,
            ));
        }

        self.cache
            .class_hash_writes
            .insert(deploy_contract_address, class_hash);
        Ok(())
    }

    fn set_compiled_class_hash(
        &mut self,
        class_hash: &Felt252,
        compiled_class_hash: &Felt252,
    ) -> Result<(), StateError> {
        let class_hash = class_hash.to_be_bytes();
        let compiled_class_hash = compiled_class_hash.to_be_bytes();

        self.cache
            .compiled_class_hash_writes
            .insert(class_hash, compiled_class_hash);
        Ok(())
    }

    fn apply_state_update(&mut self, state_updates: &StateDiff) -> Result<(), StateError> {
        let storage_updates = to_cache_state_storage_mapping(&state_updates.storage_updates);

        self.cache.update_writes(
            &state_updates.address_to_class_hash,
            &state_updates.class_hash_to_compiled_class,
            &state_updates.address_to_nonce,
            &storage_updates,
        );
        Ok(())
    }

    fn count_actual_state_changes(
        &mut self,
        fee_token_and_sender_address: Option<(&Address, &Address)>,
    ) -> Result<StateChangesCount, StateError> {
        self.update_initial_values_of_write_only_accesses()?;

        let mut storage_updates = subtract_mappings(
            &self.cache.storage_writes,
            &self.cache.storage_initial_values,
        );

        let storage_unique_updates = storage_updates.keys().map(|k| k.0.clone());

        let class_hash_updates: Vec<&Address> = subtract_mappings_keys(
            &self.cache.class_hash_writes,
            &self.cache.class_hash_initial_values,
        )
        .collect();
        let n_class_hash_updates = class_hash_updates.len();

        let compiled_class_hash_updates = subtract_mappings_keys(
            &self.cache.compiled_class_hash_writes,
            &self.cache.compiled_class_hash_initial_values,
        );

        let nonce_updates =
            subtract_mappings_keys(&self.cache.nonce_writes, &self.cache.nonce_initial_values);

        let mut modified_contracts: HashSet<Address> = HashSet::new();
        modified_contracts.extend(storage_unique_updates);
        modified_contracts.extend(class_hash_updates.into_iter().cloned());
        modified_contracts.extend(nonce_updates.cloned());

        // Add fee transfer storage update before actually charging it, as it needs to be included in the
        // calculation of the final fee.
        if let Some((fee_token_address, sender_address)) = fee_token_and_sender_address {
            let (sender_low_key, _) = get_erc20_balance_var_addresses(sender_address)?;
            storage_updates.insert(
                (fee_token_address.clone(), sender_low_key),
                Felt252::default(),
            );
            modified_contracts.remove(fee_token_address);
        }

        Ok(StateChangesCount {
            n_storage_updates: storage_updates.len(),
            n_class_hash_updates,
            n_compiled_class_hash_updates: compiled_class_hash_updates.count(),
            n_modified_contracts: modified_contracts.len(),
        })
    }

    /// Returns the class hash for a given contract address.
    /// Returns zero as default value if missing
    /// Adds the value to the cache's inital_values if not present
    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<ClassHash, StateError> {
        match self.cache.get_class_hash(contract_address).cloned() {
            Some(class_hash) => {
                self.add_hit();
                Ok(class_hash)
            }
            None => {
                self.add_miss();
                let class_hash = self.state_reader.get_class_hash_at(contract_address)?;
                self.cache
                    .class_hash_initial_values
                    .insert(contract_address.clone(), class_hash);
                Ok(class_hash)
            }
        }
    }

    fn get_nonce_at(&mut self, contract_address: &Address) -> Result<Felt252, StateError> {
        if self.cache.get_nonce(contract_address).is_none() {
            self.add_miss();
            let nonce = self.state_reader.get_nonce_at(contract_address)?;
            self.cache
                .nonce_initial_values
                .insert(contract_address.clone(), nonce);
        } else {
            self.add_hit();
        }
        Ok(self
            .cache
            .get_nonce(contract_address)
            .unwrap_or(&Felt252::zero())
            .clone())
    }

    /// Returns storage data for a given storage entry.
    /// Returns zero as default value if missing
    /// Adds the value to the cache's inital_values if not present
    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
        match self.cache.get_storage(storage_entry).cloned() {
            Some(value) => {
                self.add_hit();
                Ok(value)
            }
            None => {
                self.add_miss();
                let value = self.state_reader.get_storage_at(storage_entry)?;
                self.cache
                    .storage_initial_values
                    .insert(storage_entry.clone(), value.clone());
                Ok(value)
            }
        }
    }

    // TODO: check if that the proper way to store it (converting hash to address)
    fn get_compiled_class_hash(&mut self, class_hash: &ClassHash) -> Result<ClassHash, StateError> {
        match self
            .cache
            .class_hash_to_compiled_class_hash
            .get(class_hash)
            .cloned()
        {
            Some(hash) => {
                self.add_hit();
                Ok(hash)
            }
            None => {
                self.add_miss();
                let compiled_class_hash = self.state_reader.get_compiled_class_hash(class_hash)?;
                let address = Address(Felt252::from_bytes_be(&compiled_class_hash));
                self.cache
                    .class_hash_initial_values
                    .insert(address, compiled_class_hash);
                Ok(compiled_class_hash)
            }
        }
    }

    fn get_contract_class(&mut self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        // This method can receive both compiled_class_hash & class_hash and return both casm and deprecated contract classes
        //, which can be on the cache or on the state_reader, different cases will be described below:
        if class_hash == UNINITIALIZED_CLASS_HASH {
            return Err(StateError::UninitiaizedClassHash);
        }

        // I: FETCHING FROM CACHE
        // deprecated contract classes dont have compiled class hashes, so we only have one case
        // `RefCell::get_mut()` provides a mutable reference without the borrowing overhead when we
        // have a mutable reference to the `RefCell` available.
        if let Some(compiled_class) = self
            .contract_class_cache_private
            .get_mut()
            .map_err(|_| StateError::FailedToReadContractClassCache)?
            .get(class_hash)
            .cloned()
        {
            self.add_hit();
            return Ok(compiled_class);
        } else if let Some(compiled_class) =
            self.contract_class_cache().get_contract_class(*class_hash)
        {
            self.add_hit();
            self.contract_class_cache_private
                .get_mut()
                .map_err(|_| StateError::FailedToReadContractClassCache)?
                .insert(*class_hash, compiled_class.clone());
            return Ok(compiled_class);
        }

        // I: CASM CONTRACT CLASS : CLASS_HASH
        if let Some(compiled_class_hash) =
            self.cache.class_hash_to_compiled_class_hash.get(class_hash)
        {
            let write_guard = self
                .contract_class_cache_private
                .get_mut()
                .map_err(|_| StateError::FailedToReadContractClassCache)?;

            // `RefCell::get_mut()` provides a mutable reference without the borrowing overhead when
            // we have a mutable reference to the `RefCell` available.
            if let Some(casm_class) = write_guard.get(compiled_class_hash).cloned() {
                self.add_hit();
                return Ok(casm_class);
            } else if let Some(casm_class) = self
                .contract_class_cache()
                .get_contract_class(*compiled_class_hash)
            {
                self.add_hit();
                self.contract_class_cache_private
                    .get_mut()
                    .map_err(|_| StateError::FailedToReadContractClassCache)?
                    .insert(*class_hash, casm_class.clone());
                return Ok(casm_class);
            }
        }

        // if let Some(sierra_compiled_class) = self
        //     .sierra_programs
        //     .as_ref()
        //     .and_then(|x| x.get(class_hash))
        // {
        //     return Ok(CompiledClass::Sierra(Arc::new(
        //         sierra_compiled_class.clone(),
        //     )));
        // }
        // II: FETCHING FROM STATE_READER
        let contract = self.state_reader.get_contract_class(class_hash)?;
        match contract {
            CompiledClass::Casm(ref casm_class) => {
                // We call this method instead of state_reader's in order to update the cache's class_hash_initial_values map
                let compiled_class_hash = self.get_compiled_class_hash(class_hash)?;
                self.set_contract_class(
                    &compiled_class_hash,
                    &CompiledClass::Casm(casm_class.clone()),
                )?;
            }
            CompiledClass::Deprecated(ref contract) => {
                self.set_contract_class(class_hash, &CompiledClass::Deprecated(contract.clone()))?
            }
            CompiledClass::Sierra(ref sierra_compiled_class) => self.set_contract_class(
                class_hash,
                &CompiledClass::Sierra(sierra_compiled_class.clone()),
            )?,
        }
        Ok(contract)
    }

    fn set_sierra_program(
        &mut self,
        compiled_class_hash: &Felt252,
        _sierra_program: Vec<BigUintAsHex>,
    ) -> Result<(), StateError> {
        let _compiled_class_hash = compiled_class_hash.to_be_bytes();

        // TODO implement
        // self.sierra_programs
        //     .as_mut()
        //     .ok_or(StateError::MissingSierraProgramsCache)?
        //     .insert(compiled_class_hash, sierra_program);
        Ok(())
    }

    fn get_sierra_program(
        &mut self,
        _class_hash: &ClassHash,
    ) -> Result<Vec<cairo_lang_utils::bigint::BigUintAsHex>, StateError> {
        todo!()
    }
}

impl<T: StateReader, C: ContractClassCache> CachedState<T, C> {
    // Updates the cache's storage_initial_values according to those in storage_writes
    // If a key is present in the storage_writes but not in storage_initial_values,
    // the initial value for that key will be fetched from the state_reader and inserted into the cache's storage_initial_values
    // The same process is applied to class hash and nonce values.
    fn update_initial_values_of_write_only_accesses(&mut self) -> Result<(), StateError> {
        // Update storage_initial_values with keys in storage_writes
        for storage_entry in self.cache.storage_writes.keys() {
            if !self
                .cache
                .storage_initial_values
                .contains_key(storage_entry)
            {
                // This key was first accessed via write, so we need to cache its initial value
                self.cache.storage_initial_values.insert(
                    storage_entry.clone(),
                    self.state_reader.get_storage_at(storage_entry)?,
                );
            }
        }
        for address in self.cache.class_hash_writes.keys() {
            if !self.cache.class_hash_initial_values.contains_key(address) {
                // This key was first accessed via write, so we need to cache its initial value
                self.cache.class_hash_initial_values.insert(
                    address.clone(),
                    self.state_reader.get_class_hash_at(address)?,
                );
            }
        }
        for contract_address in self.cache.nonce_writes.keys() {
            if !self
                .cache
                .nonce_initial_values
                .contains_key(contract_address)
            {
                // This key was first accessed via write, so we need to cache its initial value
                self.cache.nonce_initial_values.insert(
                    contract_address.clone(),
                    self.state_reader.get_nonce_at(contract_address)?,
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        services::api::contract_classes::deprecated_contract_class::ContractClass,
        state::{
            contract_class_cache::PermanentContractClassCache,
            in_memory_state_reader::InMemoryStateReader,
        },
    };
    use num_traits::One;
    use std::collections::HashMap;

    /// Test checks if class hashes and nonces are correctly fetched from the state reader.
    /// It also tests the increment_nonce method.
    #[test]
    fn get_class_hash_and_nonce_from_state_reader() {
        let mut state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let contract_address = Address(4242.into());
        let class_hash = [3; 32];
        let nonce = Felt252::new(47602);
        let storage_entry = (contract_address.clone(), [101; 32]);
        let storage_value = Felt252::new(1);

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(contract_address.clone(), nonce.clone());
        state_reader
            .address_to_storage_mut()
            .insert(storage_entry, storage_value);

        let mut cached_state = CachedState::new(
            Arc::new(state_reader),
            Arc::new(PermanentContractClassCache::default()),
        );

        assert_eq!(
            cached_state.get_class_hash_at(&contract_address).unwrap(),
            class_hash
        );
        assert_eq!(cached_state.get_nonce_at(&contract_address).unwrap(), nonce);
        cached_state.increment_nonce(&contract_address).unwrap();
        assert_eq!(
            cached_state.get_nonce_at(&contract_address).unwrap(),
            nonce + Felt252::new(1)
        );
    }

    /// This test checks if the contract class is correctly fetched from the state reader.
    #[test]
    fn get_contract_class_from_state_reader() {
        let mut state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );
        let contract_class =
            ContractClass::from_path("starknet_programs/raw_contract_classes/class_with_abi.json")
                .unwrap();

        state_reader
            .class_hash_to_compiled_class
            .insert([1; 32], CompiledClass::Deprecated(Arc::new(contract_class)));

        let cached_state = CachedState::new(
            Arc::new(state_reader),
            Arc::new(PermanentContractClassCache::default()),
        );

        assert_eq!(
            cached_state.get_contract_class(&[1; 32]).unwrap(),
            cached_state
                .state_reader
                .get_contract_class(&[1; 32])
                .unwrap()
        );
    }

    /// This test verifies the correct handling of storage in the cached state.
    #[test]
    fn cached_state_storage_test() {
        let mut cached_state = CachedState::new(
            Arc::new(InMemoryStateReader::default()),
            Arc::new(PermanentContractClassCache::default()),
        );

        let storage_entry: StorageEntry = (Address(31.into()), [0; 32]);
        let value = Felt252::new(10);
        cached_state.set_storage_at(&storage_entry, value.clone());

        assert_eq!(cached_state.get_storage_at(&storage_entry).unwrap(), value);

        let storage_entry_2: StorageEntry = (Address(150.into()), [1; 32]);
        assert!(cached_state
            .get_storage_at(&storage_entry_2)
            .unwrap()
            .is_zero());
    }

    /// This test checks if deploying a contract works as expected.
    #[test]
    fn cached_state_deploy_contract_test() {
        let state_reader = Arc::new(InMemoryStateReader::default());

        let contract_address = Address(32123.into());

        let mut cached_state = CachedState::new(
            state_reader,
            Arc::new(PermanentContractClassCache::default()),
        );

        assert!(cached_state
            .deploy_contract(contract_address, [10; 32])
            .is_ok());
    }

    /// This test verifies the set and get storage values in the cached state.
    #[test]
    fn get_and_set_storage() {
        let state_reader = Arc::new(InMemoryStateReader::default());

        let contract_address = Address(31.into());
        let storage_key = [18; 32];
        let value = Felt252::new(912);

        let mut cached_state = CachedState::new(
            state_reader,
            Arc::new(PermanentContractClassCache::default()),
        );

        // set storage_key
        cached_state.set_storage_at(&(contract_address.clone(), storage_key), value.clone());
        let result = cached_state.get_storage_at(&(contract_address.clone(), storage_key));

        assert_eq!(result.unwrap(), value);

        // rewrite storage_key
        let new_value = value + 3_usize;

        cached_state.set_storage_at(&(contract_address.clone(), storage_key), new_value.clone());

        let new_result = cached_state.get_storage_at(&(contract_address, storage_key));

        assert_eq!(new_result.unwrap(), new_value);
    }

    /// This test ensures that an error is thrown if a contract address is out of range.
    #[test]
    fn deploy_contract_address_out_of_range_error_test() {
        let state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let contract_address = Address(0.into());

        let mut cached_state = CachedState::new(
            Arc::new(state_reader),
            Arc::new(PermanentContractClassCache::default()),
        );

        let result = cached_state
            .deploy_contract(contract_address.clone(), [10; 32])
            .unwrap_err();

        assert_matches!(
            result,
            StateError::ContractAddressOutOfRangeAddress(addr) if addr == contract_address
        );
    }

    /// This test ensures that an error is thrown if a contract address is already in use.
    #[test]
    fn deploy_contract_address_in_use_error_test() {
        let state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let contract_address = Address(42.into());

        let mut cached_state = CachedState::new(
            Arc::new(state_reader),
            Arc::new(PermanentContractClassCache::default()),
        );

        cached_state
            .deploy_contract(contract_address.clone(), [10; 32])
            .unwrap();
        let result = cached_state
            .deploy_contract(contract_address.clone(), [10; 32])
            .unwrap_err();

        assert_matches!(
            result,
            StateError::ContractAddressUnavailable(addr) if addr == contract_address
        );
    }

    /// This test checks if replacing a contract in the cached state works correctly.
    #[test]
    fn cached_state_replace_contract_test() {
        let state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let contract_address = Address(32123.into());

        let mut cached_state = CachedState::new(
            Arc::new(state_reader),
            Arc::new(PermanentContractClassCache::default()),
        );

        cached_state
            .deploy_contract(contract_address.clone(), [10; 32])
            .unwrap();

        assert!(cached_state
            .set_class_hash_at(contract_address.clone(), [12; 32])
            .is_ok());

        assert_matches!(
            cached_state.get_class_hash_at(&contract_address),
            Ok(class_hash) if class_hash == [12u8; 32]
        );
    }

    /// This test verifies  if the cached state's internal structures are correctly updated after applying a state update.
    #[test]
    fn cached_state_apply_state_update() {
        let state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let address_one = Address(Felt252::one());

        let mut cached_state = CachedState::new(
            Arc::new(state_reader),
            Arc::new(PermanentContractClassCache::default()),
        );

        let state_diff = StateDiff {
            address_to_class_hash: HashMap::from([(
                address_one.clone(),
                Felt252::one().to_be_bytes(),
            )]),
            address_to_nonce: HashMap::from([(address_one.clone(), Felt252::one())]),
            class_hash_to_compiled_class: HashMap::new(),
            storage_updates: HashMap::new(),
        };
        assert!(cached_state.apply_state_update(&state_diff).is_ok());
        assert!(cached_state
            .cache
            .nonce_writes
            .get(&address_one)
            .unwrap()
            .is_one());
        assert!(Felt252::from_bytes_be(
            cached_state
                .cache
                .class_hash_writes
                .get(&address_one)
                .unwrap()
        )
        .is_one());
        assert!(cached_state.cache.storage_writes.is_empty());
        assert!(cached_state.cache.nonce_initial_values.is_empty());
        assert!(cached_state.cache.class_hash_initial_values.is_empty());
    }

    /// This test calculate the number of actual storage changes.
    #[test]
    fn count_actual_state_changes_test() {
        let state_reader = InMemoryStateReader::default();
        let mut cached_state = CachedState::new(
            Arc::new(state_reader),
            Arc::new(PermanentContractClassCache::default()),
        );

        let address_one = Address(1.into());
        let address_two = Address(2.into());
        let storage_key_one = Felt252::from(1).to_be_bytes();
        let storage_key_two = Felt252::from(2).to_be_bytes();

        cached_state.cache.storage_initial_values =
            HashMap::from([((address_one.clone(), storage_key_one), Felt252::from(1))]);
        cached_state.cache.storage_writes = HashMap::from([
            ((address_one.clone(), storage_key_one), Felt252::from(1)),
            ((address_one.clone(), storage_key_two), Felt252::from(1)),
            ((address_two.clone(), storage_key_one), Felt252::from(1)),
            ((address_two.clone(), storage_key_two), Felt252::from(1)),
        ]);

        let fee_token_address = Address(123.into());
        let sender_address = Address(321.into());

        let expected_changes = StateChangesCount {
            n_storage_updates: 3 + 1, // + 1 fee transfer balance update,
            n_class_hash_updates: 0,
            n_compiled_class_hash_updates: 0,
            n_modified_contracts: 2,
        };

        let changes = cached_state
            .count_actual_state_changes(Some((&fee_token_address, &sender_address)))
            .unwrap();

        assert_eq!(changes, expected_changes);

        // Check that the initial values were updated when counting changes
        assert_eq!(
            cached_state.cache.storage_initial_values,
            HashMap::from([
                ((address_one.clone(), storage_key_one), Felt252::from(1)),
                ((address_one, storage_key_two), Felt252::from(0)),
                ((address_two.clone(), storage_key_one), Felt252::from(0)),
                ((address_two, storage_key_two), Felt252::from(0)),
            ])
        )
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn test_cache_hit_miss_counter() {
        let state_reader = Arc::new(InMemoryStateReader::default());
        let mut cached_state = CachedState::new(
            state_reader,
            Arc::new(PermanentContractClassCache::default()),
        );

        let address = Address(1.into());

        // Simulate a cache miss by querying an address not in the cache.
        let _ = <CachedState<_, _> as State>::get_class_hash_at(&mut cached_state, &address);
        assert_eq!(cached_state.cache_misses, 1);
        assert_eq!(cached_state.cache_hits, 0);

        // Simulate a cache hit by adding the address to the cache and querying it again.
        cached_state
            .cache
            .class_hash_writes
            .insert(address.clone(), [0; 32]);
        let _ = <CachedState<_, _> as State>::get_class_hash_at(&mut cached_state, &address);
        assert_eq!(cached_state.cache_misses, 1);
        assert_eq!(cached_state.cache_hits, 1);

        // Simulate another cache hit.
        let _ = <CachedState<_, _> as State>::get_class_hash_at(&mut cached_state, &address);
        assert_eq!(cached_state.cache_misses, 1);
        assert_eq!(cached_state.cache_hits, 2);

        // Simulate another cache miss.
        let other_address = Address(2.into());
        let _ = <CachedState<_, _> as State>::get_class_hash_at(&mut cached_state, &other_address);
        assert_eq!(cached_state.cache_misses, 2);
        assert_eq!(cached_state.cache_hits, 2);
    }
}
