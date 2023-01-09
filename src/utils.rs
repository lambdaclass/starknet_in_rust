use std::{collections::HashMap, hash::Hash};

use crate::{
    business_logic::state::{state_api::State, state_cache::StorageEntry},
    core::errors::{state_errors::StateError, syscall_handler_errors::SyscallHandlerError},
};
use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;

//* -------------------
//* Helper Functions
//* -------------------

pub fn get_integer(
    vm: &VirtualMachine,
    syscall_ptr: &Relocatable,
) -> Result<usize, SyscallHandlerError> {
    vm.get_integer(syscall_ptr)
        .map_err(|_| SyscallHandlerError::SegmentationFault)?
        .as_ref()
        .to_usize()
        .ok_or(SyscallHandlerError::BigintToUsizeFail)
}

pub fn get_big_int(
    vm: &VirtualMachine,
    syscall_ptr: &Relocatable,
) -> Result<BigInt, SyscallHandlerError> {
    Ok(vm
        .get_integer(syscall_ptr)
        .map_err(|_| SyscallHandlerError::SegmentationFault)?
        .into_owned())
}

pub fn get_relocatable(
    vm: &VirtualMachine,
    syscall_ptr: &Relocatable,
) -> Result<Relocatable, SyscallHandlerError> {
    vm.get_relocatable(syscall_ptr)
        .map_err(|_| SyscallHandlerError::SegmentationFault)
}

pub fn bigint_to_usize(bigint: &BigInt) -> Result<usize, SyscallHandlerError> {
    bigint
        .to_usize()
        .ok_or(SyscallHandlerError::BigintToUsizeFail)
}

pub fn get_integer_range(
    vm: &VirtualMachine,
    addr: &Relocatable,
    size: usize,
) -> Result<Vec<BigInt>, SyscallHandlerError> {
    Ok(vm
        .get_integer_range(addr, size)
        .map_err(|_| SyscallHandlerError::SegmentationFault)?
        .into_iter()
        .map(|c| c.into_owned())
        .collect::<Vec<BigInt>>())
}

pub fn bigint_to_felt(value: &BigInt) -> Result<FieldElement, SyscallHandlerError> {
    FieldElement::from_dec_str(&value.to_str_radix(10))
        .map_err(|_| SyscallHandlerError::FailToComputeHash)
}

pub fn felt_to_bigint(sign: Sign, felt: &FieldElement) -> BigInt {
    BigInt::from_bytes_be(sign, &felt.to_bytes_be())
}

// -------------------
// ~~~~~~~~~~~~~~~~~~~
//    STATE UTILS
// ~~~~~~~~~~~~~~~~~~~
// -------------------

/// Converts CachedState storage mapping to StateDiff storage mapping.
/// See to_cached_state_storage_mapping documentation.

pub fn to_state_diff_storage_mapping(
    storage_writes: HashMap<StorageEntry, BigInt>,
) -> Result<HashMap<BigInt, HashMap<[u8; 32], BigInt>>, StateError> {
    let mut storage_updates: HashMap<BigInt, HashMap<[u8; 32], BigInt>> = HashMap::new();
    for ((address, key), value) in storage_writes {
        if storage_updates.contains_key(&address) {
            let mut map = storage_updates
                .get(&address)
                .ok_or(StateError::EmptyKeyInStorage)?
                .to_owned();
            map.insert(key, value);
            storage_updates.insert(address, map);
        } else {
            let mut new_map = HashMap::new();
            new_map.insert(key, value);
            storage_updates.insert(address, new_map);
        }
    }

    Ok(storage_updates)
}


//* -------------------
//* Macros
//* -------------------

#[macro_export]
macro_rules! bigint_str {
    ($val: expr) => {
        BigInt::parse_bytes($val, 10).unwrap()
    };
    ($val: expr, $opt: expr) => {
        BigInt::parse_bytes($val, $opt).unwrap()
    };
}
pub(crate) use bigint_str;
use starknet_crypto::FieldElement;

#[macro_export]
macro_rules! bigint {
    ($val : expr) => {
        Into::<BigInt>::into($val)
    };
}

#[cfg(test)]
#[macro_use]
pub mod test_utils {

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
                cairo_rs::hint_processor::hint_processor_definition::HintReference,
            >::new();
            for i in 0..$num {
                references.insert(
                    i as usize,
                    cairo_rs::hint_processor::hint_processor_definition::HintReference::new_simple(
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
                let mut ids_data = HashMap::<String, cairo_rs::hint_processor::hint_processor_definition::HintReference>::new();
                for (i, name) in ids_names.iter().enumerate() {
                    ids_data.insert(name.to_string(), references.get(&i).unwrap().clone());
                }
                ids_data
            }
        };
    }
    pub(crate) use ids_data;

    macro_rules! vm {
        () => {{
            VirtualMachine::new(
                BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
                false,
                Vec::new(),
            )
        }};

        ($use_trace:expr) => {{
            VirtualMachine::new(
                BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
                $use_trace,
                Vec::new(),
            )
        }};
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
            $vm.insert_value(&k, &v).unwrap();
        };
        ($vm: expr, $si:expr, $off:expr, $val:expr) => {
            let v = bigint!($val);
            let k = $crate::relocatable_value!($si, $off);
            $vm.insert_value(&k, v).unwrap();
        };
    }
    pub(crate) use allocate_values;

    #[macro_export]
    macro_rules! allocate_selector {
        ($vm: expr, (($si:expr, $off:expr), $val:expr)) => {
            let v = $crate::bigint_str!($val);
            let k = $crate::relocatable_value!($si, $off);
            $vm.insert_value(&k, v).unwrap();
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
            let mut hint_processor = SyscallHintProcessor::new_empty().unwrap();
            hint_processor.execute_hint(
                &mut $vm,
                exec_scopes_ref!(),
                &any_box!(hint_data),
                &HashMap::new(),
            )
        }};
    }
    pub(crate) use run_syscall_hint;

    macro_rules! storage_key {
        ( $key:literal ) => {{
            assert_eq!($key.len(), 64, "keys must be 64 nibbles in length.");
            let key: [u8; 32] = $key
                .as_bytes()
                .chunks_exact(2)
                .map(|x| {
                    u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16)
                        .expect("Key contains non-hexadecimal characters.")
                })
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap();

            key
        }};
    }
    pub(crate) use storage_key;
}

#[cfg(test)]
mod test {
    use num_bigint::BigInt;
    use std::collections::HashMap;

    use super::{test_utils::storage_key, to_state_diff_storage_mapping};
    use crate::bigint;

    #[test]
    fn to_state_diff_storage_mapping_test() {
        let mut storage: HashMap<(BigInt, [u8; 32]), BigInt> = HashMap::new();
        let address1 = bigint!(1);
        let key1 = storage_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let value1 = bigint!(2);

        let address2 = bigint!(3);
        let key2 = storage_key!("0000000000000000000000000000000000000000000000000000000000000001");
        let value2 = bigint!(4);

        storage.insert((address1.clone(), key1), value1.clone());
        storage.insert((address2.clone(), key2), value2.clone());

        let map = to_state_diff_storage_mapping(storage).unwrap();

        assert_eq!(*map.get(&address1).unwrap().get(&key1).unwrap(), value1);
        assert_eq!(*map.get(&address2).unwrap().get(&key2).unwrap(), value2);
    }
}
