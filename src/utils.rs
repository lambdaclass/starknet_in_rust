use crate::{
    business_logic::{
        execution::{
            gas_usage::calculate_tx_gas_usage, objects::CallInfo,
            os_usage::get_additional_os_resources,
        },
        fact_state::state::ExecutionResourcesManager,
        state::{
            cached_state::UNINITIALIZED_CLASS_HASH, state_api::StateReader,
            state_cache::StorageEntry,
        },
        transaction::error::TransactionError,
    },
    core::errors::syscall_handler_errors::SyscallHandlerError,
    definitions::transaction_type::TransactionType,
    services::api::contract_classes::deprecated_contract_class::EntryPointType,
};
use cairo_vm::{
    felt::Felt252, serde::deserialize_program::BuiltinName, vm::runners::builtin_runner,
};
use cairo_vm::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use num_traits::{Num, ToPrimitive};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use starknet_crypto::FieldElement;
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

pub type ClassHash = [u8; 32];
pub type CompiledClassHash = [u8; 32];

//* -------------------
//*      Address
//* -------------------

#[derive(Debug, Clone, PartialEq, Hash, Eq, Default, Serialize, Deserialize)]
pub struct Address(pub Felt252);

//* -------------------
//*  Helper Functions
//* -------------------

pub fn get_integer(
    vm: &VirtualMachine,
    syscall_ptr: Relocatable,
) -> Result<usize, SyscallHandlerError> {
    vm.get_integer(syscall_ptr)?
        .as_ref()
        .to_usize()
        .ok_or(SyscallHandlerError::FeltToUsizeFail)
}

pub fn get_big_int(
    vm: &VirtualMachine,
    syscall_ptr: Relocatable,
) -> Result<Felt252, SyscallHandlerError> {
    Ok(vm.get_integer(syscall_ptr)?.into_owned())
}

pub fn get_relocatable(
    vm: &VirtualMachine,
    syscall_ptr: Relocatable,
) -> Result<Relocatable, SyscallHandlerError> {
    Ok(vm.get_relocatable(syscall_ptr)?)
}

pub fn get_integer_range(
    vm: &VirtualMachine,
    addr: Relocatable,
    size: usize,
) -> Result<Vec<Felt252>, SyscallHandlerError> {
    Ok(vm
        .get_integer_range(addr, size)?
        .into_iter()
        .map(|c| c.into_owned())
        .collect::<Vec<Felt252>>())
}

pub fn get_felt_range(
    vm: &VirtualMachine,
    start_addr: Relocatable,
    end_addr: Relocatable,
) -> Result<Vec<Felt252>, SyscallHandlerError> {
    if start_addr.segment_index != end_addr.segment_index {
        return Err(SyscallHandlerError::InconsistentSegmentIndices);
    }

    if start_addr.offset > end_addr.offset {
        return Err(SyscallHandlerError::StartOffsetGreaterThanEndOffset);
    }

    let size = end_addr.offset - start_addr.offset;
    get_integer_range(vm, start_addr, size)
}

pub fn felt_to_field_element(value: &Felt252) -> Result<FieldElement, SyscallHandlerError> {
    FieldElement::from_dec_str(&value.to_str_radix(10))
        .map_err(|_| SyscallHandlerError::FailToComputeHash)
}

pub fn field_element_to_felt(felt: &FieldElement) -> Felt252 {
    Felt252::from_bytes_be(&felt.to_bytes_be())
}

pub fn felt_to_hash(value: &Felt252) -> ClassHash {
    let mut output = [0; 32];

    let bytes = value.to_bytes_be();
    output[32 - bytes.len()..].copy_from_slice(&bytes);

    output
}

pub fn string_to_hash(class_string: &String) -> ClassHash {
    let parsed_felt = Felt252::from_str_radix(
        if &class_string[..2] == "0x" {
            &class_string[2..]
        } else {
            class_string
        },
        16,
    );
    felt_to_hash(&parsed_felt.unwrap())
}

// -------------------
//    STATE UTILS
// -------------------

/// Converts CachedState storage mapping to StateDiff storage mapping.
/// See to_cached_state_storage_mapping documentation.

pub fn to_state_diff_storage_mapping(
    storage_writes: HashMap<StorageEntry, Felt252>,
) -> HashMap<Felt252, HashMap<ClassHash, Address>> {
    let mut storage_updates: HashMap<Felt252, HashMap<ClassHash, Address>> = HashMap::new();
    for ((address, key), value) in storage_writes {
        let mut map = storage_updates.get(&address.0).cloned().unwrap_or_default();
        map.insert(key, Address(value));
        storage_updates.insert(address.0, map);
    }
    storage_updates
}

/// Returns the total resources needed to include the most recent transaction in a StarkNet batch
/// (recent w.r.t. application on the given state) i.e., L1 gas usage and Cairo execution resources.
/// Used for transaction fee; calculation is made as if the transaction is the first in batch, for
/// consistency.

pub fn get_call_n_deployments(call_info: &CallInfo) -> usize {
    call_info
        .gen_call_topology()
        .iter()
        .fold(0, |acc, c| match c.entry_point_type {
            Some(EntryPointType::Constructor) => acc + 1,
            _ => acc,
        })
}

pub fn calculate_tx_resources(
    resources_manager: ExecutionResourcesManager,
    call_info: &[Option<CallInfo>],
    tx_type: TransactionType,
    storage_changes: (usize, usize),
    l1_handler_payload_size: Option<usize>,
) -> Result<HashMap<String, usize>, TransactionError> {
    let (n_modified_contracts, n_storage_changes) = storage_changes;

    let non_optional_calls: Vec<CallInfo> = call_info.iter().flatten().cloned().collect();
    let n_deployments = non_optional_calls.iter().map(get_call_n_deployments).sum();

    let mut l2_to_l1_messages = Vec::new();

    for call_info in non_optional_calls {
        l2_to_l1_messages.extend(call_info.get_sorted_l2_to_l1_messages()?)
    }

    let l1_gas_usage = calculate_tx_gas_usage(
        l2_to_l1_messages,
        n_modified_contracts,
        n_storage_changes,
        l1_handler_payload_size,
        n_deployments,
    );

    let cairo_usage = resources_manager.cairo_usage.clone();
    let tx_syscall_counter = resources_manager.syscall_counter;

    // Add additional Cairo resources needed for the OS to run the transaction.
    let additional_resources = get_additional_os_resources(tx_syscall_counter, &tx_type)?;
    let new_resources = &cairo_usage + &additional_resources;
    let filtered_builtins = new_resources.filter_unused_builtins();

    let mut resources: HashMap<String, usize> = HashMap::new();
    resources.insert("l1_gas_usage".to_string(), l1_gas_usage);
    for (builtin, value) in filtered_builtins.builtin_instance_counter {
        resources.insert(builtin, value);
    }

    Ok(resources)
}

/// Returns a mapping containing key-value pairs from a that are not included in b (if
/// a key appears in b with a different value, it will be part of the output).
/// Uses to take only updated cells from a mapping.

fn contained_and_not_updated<K, V>(key: &K, value: &V, map: &HashMap<K, V>) -> bool
where
    K: Hash + Eq,
    V: PartialEq + Clone,
{
    let val = map.get(key);
    !(map.contains_key(key) && (Some(value) == val))
}

pub fn subtract_mappings<K, V>(map_a: HashMap<K, V>, map_b: HashMap<K, V>) -> HashMap<K, V>
where
    K: Hash + Eq + Clone,
    V: PartialEq + Clone,
{
    map_a
        .into_iter()
        .filter(|(k, v)| contained_and_not_updated(k, v, &map_b))
        .collect()
}

/// Converts StateDiff storage mapping (addresses map to a key-value mapping) to CachedState
/// storage mapping (Tuple of address and key map to the associated value).

pub fn to_cache_state_storage_mapping(
    map: HashMap<Felt252, HashMap<ClassHash, Address>>,
) -> HashMap<StorageEntry, Felt252> {
    let mut storage_writes = HashMap::new();
    for (address, contract_storage) in map {
        for (key, value) in contract_storage {
            storage_writes.insert((Address(address.clone()), key), value.0);
        }
    }
    storage_writes
}

// get a vector of keys from two hashmaps

pub fn get_keys<K, V>(map_a: HashMap<K, V>, map_b: HashMap<K, V>) -> Vec<K>
where
    K: Hash + Eq,
{
    let mut keys1: HashSet<K> = map_a.into_keys().collect();
    let keys2: HashSet<K> = map_b.into_keys().collect();

    keys1.extend(keys2);

    keys1.into_iter().collect()
}

//* ----------------------------
//* Execution entry point utils
//* ----------------------------

pub fn get_deployed_address_class_hash_at_address<S: StateReader>(
    state: &mut S,
    contract_address: &Address,
) -> Result<ClassHash, TransactionError> {
    let class_hash: ClassHash = state
        .get_class_hash_at(contract_address)
        .map_err(|_| TransactionError::FailToReadClassHash)?
        .to_owned();

    if class_hash == *UNINITIALIZED_CLASS_HASH {
        return Err(TransactionError::NotDeployedContract(class_hash));
    }
    Ok(class_hash)
}

pub fn validate_contract_deployed<S: StateReader>(
    state: &mut S,
    contract_address: &Address,
) -> Result<ClassHash, TransactionError> {
    get_deployed_address_class_hash_at_address(state, contract_address)
}

//* ----------------------------
//* Internal objects utils
//* ----------------------------

pub(crate) fn verify_no_calls_to_other_contracts(
    call_info: &CallInfo,
) -> Result<(), TransactionError> {
    let invoked_contract_address = call_info.contract_address.clone();
    for internal_call in call_info.gen_call_topology() {
        if internal_call.contract_address != invoked_contract_address {
            return Err(TransactionError::UnauthorizedActionOnValidate);
        }
    }
    Ok(())
}
pub fn calculate_sn_keccak(data: &[u8]) -> ClassHash {
    let mut hasher = Keccak256::default();
    hasher.update(data);
    let mut result: ClassHash = hasher.finalize().into();
    // Only the first 250 bits from the hash are used.
    result[0] &= 0b0000_0011;
    result
}

//* ------------------------
//*      Other utils
//* ------------------------

pub(crate) fn parse_builtin_names(
    builtin_strings: &[String],
) -> Result<Vec<BuiltinName>, TransactionError> {
    builtin_strings
        .iter()
        .map(|n| format!("{n}_builtin"))
        .map(|s| match &*s {
            builtin_runner::OUTPUT_BUILTIN_NAME => Ok(BuiltinName::output),
            builtin_runner::RANGE_CHECK_BUILTIN_NAME => Ok(BuiltinName::range_check),
            builtin_runner::HASH_BUILTIN_NAME => Ok(BuiltinName::pedersen),
            builtin_runner::SIGNATURE_BUILTIN_NAME => Ok(BuiltinName::ecdsa),
            builtin_runner::KECCAK_BUILTIN_NAME => Ok(BuiltinName::keccak),
            builtin_runner::BITWISE_BUILTIN_NAME => Ok(BuiltinName::bitwise),
            builtin_runner::EC_OP_BUILTIN_NAME => Ok(BuiltinName::ec_op),
            builtin_runner::POSEIDON_BUILTIN_NAME => Ok(BuiltinName::poseidon),
            builtin_runner::SEGMENT_ARENA_BUILTIN_NAME => Ok(BuiltinName::segment_arena),
            s => Err(TransactionError::InvalidBuiltinContractClass(s.to_string())),
        })
        .collect()
}

//* -------------------
//*      Macros
//* -------------------

#[cfg(test)]
#[macro_use]
pub mod test_utils {
    #![allow(unused_imports)]

    #[macro_export]
    macro_rules! any_box {
        ($val : expr) => {
            Box::new($val) as Box<dyn Any>
        };
    }
    pub(crate) use any_box;

    macro_rules! references {
        ($num: expr) => {{
            let mut references = HashMap::<
                usize,
                cairo_vm::hint_processor::hint_processor_definition::HintReference,
            >::new();
            for i in 0..$num {
                references.insert(
                    i as usize,
                    cairo_vm::hint_processor::hint_processor_definition::HintReference::new_simple(
                        (i as i32),
                    ),
                );
            }
            references
        }};
    }
    pub(crate) use references;

    macro_rules! ids_data {
        ( $( $name: expr ),* ) => {
            {
                let ids_names = vec![$( $name ),*];
                let references = $crate::utils::test_utils::references!(ids_names.len() as i32);
                let mut ids_data = HashMap::<String, cairo_vm::hint_processor::hint_processor_definition::HintReference>::new();
                for (i, name) in ids_names.iter().enumerate() {
                    ids_data.insert(name.to_string(), references.get(&i).unwrap().clone());
                }
                ids_data
            }
        };
    }
    pub(crate) use ids_data;

    macro_rules! vm {
        () => {
            VirtualMachine::new(false)
        };

        ($use_trace:expr) => {
            VirtualMachine::new($use_trace, Vec::new())
        };
    }
    pub(crate) use vm;

    #[macro_export]
    macro_rules! add_segments {
        ($vm:expr, $n:expr) => {
            for _ in 0..$n {
                $vm.add_memory_segment();
            }
        };
    }
    pub(crate) use add_segments;

    #[macro_export]
    macro_rules! memory_insert {
        ($vm:expr, [ $( (($si:expr, $off:expr), $val:tt) ),* ] ) => {
            $( $crate::allocate_values!($vm, $si, $off, $val); )*
        };
    }
    pub(crate) use memory_insert;

    #[macro_export]
    macro_rules! allocate_values {
        ($vm: expr, $si:expr, $off:expr, ($sival:expr, $offval:expr)) => {
            let k = $crate::relocatable_value!($si, $off);
            let v = $crate::relocatable_value!($sival, $offval);
            $vm.insert_value(k, &v).unwrap();
        };
        ($vm: expr, $si:expr, $off:expr, $val:expr) => {
            let v: cairo_vm::felt::Felt252 = $val.into();
            let k = $crate::relocatable_value!($si, $off);
            $vm.insert_value(k, v).unwrap();
        };
    }
    pub(crate) use allocate_values;

    #[macro_export]
    macro_rules! allocate_selector {
        ($vm: expr, (($si:expr, $off:expr), $val:expr)) => {
            let v = cairo_vm::felt::Felt252::from_bytes_be($val);
            let k = $crate::relocatable_value!($si, $off);
            $vm.insert_value(k, v).unwrap();
        };
    }
    pub(crate) use allocate_selector;

    #[macro_export]
    macro_rules! relocatable_value {
        ($val1 : expr, $val2 : expr) => {
            Relocatable {
                segment_index: ($val1),
                offset: ($val2),
            }
        };
    }
    pub(crate) use relocatable_value;

    #[macro_export]
    macro_rules! exec_scopes_ref {
        () => {
            &mut ExecutionScopes::new()
        };
    }
    pub(crate) use exec_scopes_ref;

    #[macro_export]
    macro_rules! run_hint {
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_scopes:expr, $constants:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(&mut $vm, $exec_scopes, &any_box!(hint_data), $constants)
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_scopes:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(
                &mut $vm,
                $exec_scopes,
                &any_box!(hint_data),
                &HashMap::new(),
            )
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let mut hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(
                &mut $vm,
                exec_scopes_ref!(),
                &any_box!(hint_data),
                &HashMap::new(),
            )
        }};
    }
    pub(crate) use run_hint;

    #[macro_export]
    macro_rules! run_syscall_hint {
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_scopes:expr, $constants:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(&mut $vm, $exec_scopes, &any_box!(hint_data), $constants)
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_scopes:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(
                &mut $vm,
                $exec_scopes,
                &any_box!(hint_data),
                &HashMap::new(),
            )
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let mut state = CachedState::<InMemoryStateReader>::default();
            let mut hint_processor = $crate::core::syscalls::syscall_handler::SyscallHintProcessor::<
                $crate::core::syscalls::business_logic_syscall_handler::DeprecatedBLSyscallHandler::<
                    $crate::business_logic::state::cached_state::CachedState<
                        $crate::business_logic::fact_state::in_memory_state_reader::InMemoryStateReader,
                    >,
                >,
            >::new(DeprecatedBLSyscallHandler::default_with(&mut state));
            hint_processor.execute_hint(
                &mut $vm,
                exec_scopes_ref!(),
                &any_box!(hint_data),
                &HashMap::new(),
            )
        }};
    }
    pub(crate) use run_syscall_hint;
}

pub mod integration_test_utils {
    use crate::{
        business_logic::{
            execution::{
                execution_entry_point::ExecutionEntryPoint,
                objects::{CallInfo, CallType, TransactionExecutionContext},
            },
            fact_state::{
                in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
            },
            state::cached_state::CachedState,
        },
        definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
        services::api::contract_classes::deprecated_contract_class::EntryPointType,
        utils::ClassHash,
    };
    use num_traits::Zero;
    use std::collections::HashMap;

    use crate::utils::Address;
    use cairo_lang_starknet::casm_contract_class::CasmContractClass;
    use cairo_vm::{felt::Felt252, vm::runners::cairo_runner::ExecutionResources};

    pub fn test_cairo_1_external_entrypoint(
        program_data: &[u8],
        entrypoint: usize,
        expected_retdata: &[Felt252],
        expected_execution_resources: &ExecutionResources,
    ) {
        let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
        let entrypoints = contract_class.clone().entry_points_by_type;
        let entrypoint_selector = &entrypoints.external.get(entrypoint).unwrap().selector;

        // Create state reader with class hash data
        let mut contract_class_cache = HashMap::new();

        let address = Address(1111.into());
        let class_hash: ClassHash = [1; 32];
        let nonce = Felt252::zero();

        contract_class_cache.insert(class_hash, contract_class);
        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(address.clone(), nonce);

        // Create state from the state_reader and contract cache.
        let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

        // Create an execution entry point
        let calldata = [0.into(), 1.into(), 12.into()].to_vec();
        let caller_address = Address(0000.into());
        let entry_point_type = EntryPointType::External;

        let exec_entry_point = ExecutionEntryPoint::new(
            address,
            calldata.clone(),
            Felt252::new(entrypoint_selector.clone()),
            caller_address,
            entry_point_type,
            Some(CallType::Delegate),
            Some(class_hash),
            100000,
        );

        // Execute the entrypoint
        let general_config = StarknetGeneralConfig::default();
        let tx_execution_context = TransactionExecutionContext::new(
            Address(0.into()),
            Felt252::zero(),
            Vec::new(),
            0,
            10.into(),
            general_config.invoke_tx_max_n_steps(),
            TRANSACTION_VERSION,
        );
        let mut resources_manager = ExecutionResourcesManager::default();

        // expected results
        let expected_call_info = CallInfo {
            caller_address: Address(0.into()),
            call_type: Some(CallType::Delegate),
            contract_address: Address(1111.into()),
            entry_point_selector: Some(Felt252::new(entrypoint_selector)),
            entry_point_type: Some(EntryPointType::External),
            calldata,
            retdata: expected_retdata.to_vec(),
            execution_resources: expected_execution_resources.clone(),
            class_hash: Some(class_hash),
            ..Default::default()
        };

        assert_eq!(
            exec_entry_point
                .execute(
                    &mut state,
                    &general_config,
                    &mut resources_manager,
                    &tx_execution_context,
                    false,
                )
                .unwrap(),
            expected_call_info
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cairo_vm::felt::{felt_str, Felt252};
    use num_traits::{One, Zero};
    use std::collections::HashMap;

    #[test]
    fn to_state_diff_storage_mapping_test() {
        let mut storage: HashMap<(Address, ClassHash), Felt252> = HashMap::new();
        let address1: Address = Address(1.into());
        let key1 = [0; 32];
        let value1: Felt252 = 2.into();

        let address2: Address = Address(3.into());
        let key2 = [1; 32];

        let value2: Felt252 = 4.into();

        storage.insert((address1.clone(), key1), value1.clone());
        storage.insert((address2.clone(), key2), value2.clone());

        let map = to_state_diff_storage_mapping(storage);

        assert_eq!(
            *map.get(&address1.0).unwrap().get(&key1).unwrap(),
            Address(value1)
        );
        assert_eq!(
            *map.get(&address2.0).unwrap().get(&key2).unwrap(),
            Address(value2)
        );
    }

    #[test]

    fn subtract_mappings_test() {
        let mut a = HashMap::new();
        let mut b = HashMap::new();

        a.insert("a", 2);
        a.insert("b", 3);

        b.insert("c", 2);
        b.insert("d", 4);
        b.insert("a", 3);

        let res = [("a", 2), ("b", 3)]
            .into_iter()
            .collect::<HashMap<&str, i32>>();

        assert_eq!(subtract_mappings(a, b), res);

        let mut c = HashMap::new();
        let mut d = HashMap::new();

        c.insert(1, 2);
        c.insert(3, 4);
        c.insert(6, 7);

        d.insert(1, 3);
        d.insert(3, 5);
        d.insert(6, 8);

        let res = [(1, 2), (3, 4), (6, 7)]
            .into_iter()
            .collect::<HashMap<i32, i32>>();

        assert_eq!(subtract_mappings(c, d), res);

        let mut e = HashMap::new();
        let mut f = HashMap::new();
        e.insert(1, 2);
        e.insert(3, 4);
        e.insert(6, 7);

        f.insert(1, 2);
        f.insert(3, 4);
        f.insert(6, 7);

        assert_eq!(subtract_mappings(e, f), HashMap::new())
    }

    #[test]

    fn to_cache_state_storage_mapping_test() {
        let mut storage: HashMap<(Address, ClassHash), Felt252> = HashMap::new();
        let address1: Address = Address(1.into());
        let key1 = [0; 32];
        let value1: Felt252 = 2.into();

        let address2: Address = Address(3.into());
        let key2 = [1; 32];

        let value2: Felt252 = 4.into();

        storage.insert((address1.clone(), key1), value1.clone());
        storage.insert((address2.clone(), key2), value2.clone());

        let state_dff = to_state_diff_storage_mapping(storage);
        let cache_storage = to_cache_state_storage_mapping(state_dff);

        let mut expected_res = HashMap::new();

        expected_res.insert((Address(address1.0), key1), value1);
        expected_res.insert((Address(address2.0), key2), value2);

        assert_eq!(cache_storage, expected_res)
    }

    #[test]
    fn test_felt_to_hash() {
        assert_eq!(felt_to_hash(&Felt252::zero()), [0; 32]);
        assert_eq!(
            felt_to_hash(&Felt252::one()),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1
            ],
        );
        assert_eq!(
            felt_to_hash(&257.into()),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 1, 1
            ],
        );

        assert_eq!(
            felt_to_hash(&felt_str!(
                "2151680050850558576753658069693146429350618838199373217695410689374331200218"
            )),
            [
                4, 193, 206, 200, 202, 13, 38, 110, 16, 37, 89, 67, 39, 3, 185, 128, 123, 117, 218,
                224, 80, 72, 144, 143, 109, 237, 203, 41, 241, 37, 226, 218
            ],
        );
    }
}
