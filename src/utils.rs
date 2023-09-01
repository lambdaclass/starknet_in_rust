use crate::core::errors::hash_errors::HashError;
use crate::definitions::constants::FEE_TRANSFER_N_STORAGE_CHANGES_TO_CHARGE;
use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;
use crate::state::state_api::State;
use crate::{
    definitions::transaction_type::TransactionType,
    execution::{
        gas_usage::calculate_tx_gas_usage, os_usage::get_additional_os_resources, CallInfo,
    },
    state::ExecutionResourcesManager,
    state::{cached_state::UNINITIALIZED_CLASS_HASH, state_cache::StorageEntry},
    syscalls::syscall_handler_errors::SyscallHandlerError,
    transaction::error::TransactionError,
};
use cairo_vm::vm::runners::builtin_runner::SEGMENT_ARENA_BUILTIN_NAME;
use cairo_vm::{
    felt::Felt252, serde::deserialize_program::BuiltinName, vm::runners::builtin_runner,
};
use cairo_vm::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use num_integer::Integer;
use num_traits::{Num, ToPrimitive};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use starknet::core::types::FromByteArrayError;
use starknet_api::core::L2_ADDRESS_UPPER_BOUND;
use starknet_crypto::{pedersen_hash, FieldElement};
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
        .ok_or(SyscallHandlerError::Conversion(
            "Felt252".to_string(),
            "usize".to_string(),
        ))
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
        .map_err(|e| SyscallHandlerError::HashError(HashError::FailedToComputeHash(e.to_string())))
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
pub fn to_state_diff_storage_mapping(
    storage_writes: HashMap<StorageEntry, Felt252>,
) -> HashMap<Address, HashMap<Felt252, Felt252>> {
    let mut storage_updates: HashMap<Address, HashMap<Felt252, Felt252>> = HashMap::new();
    for ((address, key), value) in storage_writes.into_iter() {
        storage_updates
            .entry(address)
            .and_modify(|updates_for_address: &mut HashMap<Felt252, Felt252>| {
                let key_fe = Felt252::from_bytes_be(&key);
                updates_for_address.insert(key_fe, value.clone());
            })
            .or_insert_with(|| HashMap::from([(Felt252::from_bytes_be(&key), value)]));
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
    n_reverted_steps: usize,
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
        n_storage_changes + FEE_TRANSFER_N_STORAGE_CHANGES_TO_CHARGE,
        l1_handler_payload_size,
        n_deployments,
    );

    let cairo_usage = resources_manager.cairo_usage.clone();
    let tx_syscall_counter = resources_manager.syscall_counter;

    // Add additional Cairo resources needed for the OS to run the transaction.
    let additional_resources = get_additional_os_resources(tx_syscall_counter, &tx_type)?;
    let new_resources = &cairo_usage + &additional_resources;
    let mut filtered_builtins = new_resources.filter_unused_builtins();

    let n_steps = new_resources.n_steps
        + n_reverted_steps
        + 10 * filtered_builtins
            .builtin_instance_counter
            .remove(SEGMENT_ARENA_BUILTIN_NAME)
            .unwrap_or(0);

    let mut resources: HashMap<String, usize> = HashMap::new();
    resources.insert("l1_gas_usage".to_string(), l1_gas_usage);
    resources.insert(
        "n_steps".to_string(),
        n_steps + filtered_builtins.n_memory_holes,
    );
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
    map: &HashMap<Address, HashMap<Felt252, Felt252>>,
) -> HashMap<StorageEntry, Felt252> {
    let mut storage_writes = HashMap::new();
    for (address, contract_storage) in map {
        for (key, value) in contract_storage {
            storage_writes.insert((address.clone(), felt_to_hash(key)), value.clone());
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

/// Returns the storage address of a StarkNet storage variable given its name and arguments.
pub fn get_storage_var_address(
    storage_var_name: &str,
    args: &[Felt252],
) -> Result<Felt252, FromByteArrayError> {
    let felt_to_field_element = |felt: &Felt252| -> Result<FieldElement, FromByteArrayError> {
        FieldElement::from_bytes_be(&felt.to_be_bytes())
    };

    let args = args
        .iter()
        .map(|felt| felt_to_field_element(felt))
        .collect::<Result<Vec<_>, _>>()?;

    let storage_var_name_hash =
        FieldElement::from_bytes_be(&calculate_sn_keccak(storage_var_name.as_bytes()))?;
    let storage_key_hash = args
        .iter()
        .fold(storage_var_name_hash, |res, arg| pedersen_hash(&res, arg));

    let storage_key = field_element_to_felt(&storage_key_hash).mod_floor(&Felt252::from_bytes_be(
        &L2_ADDRESS_UPPER_BOUND.to_bytes_be(),
    ));

    Ok(storage_key)
}

/// Gets storage keys for a Uint256 storage variable.
pub fn get_uint256_storage_var_addresses(
    storage_var_name: &str,
    args: &[Felt252],
) -> Result<(Felt252, Felt252), FromByteArrayError> {
    let low_key = get_storage_var_address(storage_var_name, args)?;
    let high_key = &low_key + &Felt252::from(1);
    Ok((low_key, high_key))
}

pub fn get_erc20_balance_var_addresses(
    contract_address: &Address,
) -> Result<([u8; 32], [u8; 32]), FromByteArrayError> {
    let (felt_low, felt_high) =
        get_uint256_storage_var_addresses("ERC20_balances", &[contract_address.clone().0])?;
    Ok((felt_low.to_be_bytes(), felt_high.to_be_bytes()))
}

//* ----------------------------
//* Execution entry point utils
//* ----------------------------

pub fn get_deployed_address_class_hash_at_address<S: State>(
    state: &mut S,
    contract_address: &Address,
) -> Result<ClassHash, TransactionError> {
    let class_hash: ClassHash = state
        .get_class_hash_at(contract_address)
        .map_err(|_| TransactionError::FailToReadClassHash)?
        .to_owned();

    if class_hash == *UNINITIALIZED_CLASS_HASH {
        return Err(TransactionError::NotDeployedContract(felt_to_hash(
            &contract_address.0,
        )));
    }
    Ok(class_hash)
}

pub fn validate_contract_deployed<S: State>(
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

/// Parses an array of strings representing Felt252 as hex
pub fn parse_felt_array(felt_strings: &[Value]) -> Vec<Felt252> {
    let mut felts = vec![];

    for felt in felt_strings {
        let felt_string = felt.as_str().unwrap();
        felts.push(match felt_string.starts_with("0x") {
            true => Felt252::parse_bytes(felt_string[2..].as_bytes(), 16).unwrap(),
            false => Felt252::parse_bytes(felt_string.as_bytes(), 16).unwrap(),
        })
    }

    felts
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
                    $crate::state::cached_state::CachedState<
                        $crate::state::in_memory_state_reader::InMemoryStateReader,
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

#[cfg(test)]
mod test {
    use super::*;
    use cairo_vm::felt::{felt_str, Felt252};
    use num_traits::{One, Zero};
    use std::collections::HashMap;

    #[test]
    fn to_state_diff_storage_mapping_test() {
        let mut storage: HashMap<(Address, [u8; 32]), Felt252> = HashMap::new();
        let address1: Address = Address(1.into());
        let key1 = [0; 32];
        let value1: Felt252 = 2.into();

        let address2: Address = Address(3.into());
        let key2 = [1; 32];

        let value2: Felt252 = 4.into();

        storage.insert((address1.clone(), key1), value1.clone());
        storage.insert((address2.clone(), key2), value2.clone());

        let map = to_state_diff_storage_mapping(storage);

        let key1_fe = Felt252::from_bytes_be(key1.as_slice());
        let key2_fe = Felt252::from_bytes_be(key2.as_slice());
        assert_eq!(*map.get(&address1).unwrap().get(&key1_fe).unwrap(), value1);
        assert_eq!(*map.get(&address2).unwrap().get(&key2_fe).unwrap(), value2);
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
        let cache_storage = to_cache_state_storage_mapping(&state_dff);

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
