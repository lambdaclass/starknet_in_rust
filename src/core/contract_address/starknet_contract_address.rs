/// Contains functionality for computing class hashes for deprecated Declare transactions
/// (ie, declarations that do not correspond to Cairo 1 contracts)
use crate::{
    core::errors::contract_address_errors::ContractAddressError,
    services::api::contract_classes::deprecated_contract_class::{
        ContractClass, ContractEntryPoint, EntryPointType,
    },
};
use cairo_vm::felt::Felt252;
use cairo_vm::{
    hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor,
    serde::deserialize_program::{BuiltinName, Identifier},
    types::{program::Program, relocatable::MaybeRelocatable},
    vm::{
        runners::{
            builtin_runner::BuiltinRunner,
            cairo_runner::{CairoArg, CairoRunner},
        },
        vm_core::VirtualMachine,
    },
};
use lazy_static::lazy_static;
use sha3::{Digest, Keccak256};

/// Instead of doing a Mask with 250 bits, we are only masking the most significant byte.
pub const MASK_3: u8 = 3;
pub const CONTRACT_STR: &str =
    include_str!("../../../cairo_programs/deprecated_compiled_class.json");

lazy_static! {
    // static ref PATH_BUF_CONTRACTS = BufReader::from(CONTRACT_STR);
    static ref HASH_CALCULATION_PROGRAM: Program =
        Program::from_bytes(CONTRACT_STR.as_bytes(), None).unwrap();
}

fn get_contract_entry_points(
    contract_class: &ContractClass,
    entry_point_type: &EntryPointType,
) -> Result<Vec<ContractEntryPoint>, ContractAddressError> {
    let program_length = contract_class.program().iter_data().count();

    let entry_points = contract_class
        .entry_points_by_type()
        .get(entry_point_type)
        .ok_or(ContractAddressError::NoneExistingEntryPointType)?;

    let program_len = program_length;
    for entry_point in entry_points {
        if entry_point.offset > program_len {
            return Err(ContractAddressError::InvalidOffset(entry_point.offset));
        }
    }
    Ok(entry_points
        .iter()
        .map(|entry_point| ContractEntryPoint {
            offset: entry_point.offset,
            selector: entry_point.selector.clone(),
        })
        .collect())
}

/// A variant of eth-keccak that computes a value that fits in a StarkNet field element.
fn starknet_keccak(data: &[u8]) -> Felt252 {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let mut finalized_hash = hasher.finalize();
    let hashed_slice: &[u8] = finalized_hash.as_slice();

    // This is the same than doing a mask 3 only with the most significant byte.
    // and then copying the other values.
    let res = hashed_slice[0] & MASK_3;
    finalized_hash[0] = res;
    Felt252::from_bytes_be(finalized_hash.as_slice())
}

/// Computes the hash of the contract class, including hints.
/// We are not supporting backward compatibility now.
fn compute_hinted_class_hash(_contract_class: &ContractClass) -> Felt252 {
    let keccak_input =
        r#"{"abi": contract_class.abi, "program": contract_class.program}"#.as_bytes();
    starknet_keccak(keccak_input)
}

/// Returns the serialization of a contract as a list of field elements.
fn get_contract_class_struct(
    api_version_identifier: &Identifier,
    contract_class: &ContractClass,
) -> Result<DeprecatedCompiledClass, ContractAddressError> {
    let external_functions = get_contract_entry_points(contract_class, &EntryPointType::External)?;
    let l1_handlers = get_contract_entry_points(contract_class, &EntryPointType::L1Handler)?;
    let constructors = get_contract_entry_points(contract_class, &EntryPointType::Constructor)?;
    let builtin_list: &Vec<BuiltinName> =
        &contract_class.program().iter_builtins().cloned().collect();

    let contract_class_data: Vec<MaybeRelocatable> =
        contract_class.program().iter_data().cloned().collect();

    Ok(DeprecatedCompiledClass {
        compiled_class_version: api_version_identifier
            .value
            .as_ref()
            .ok_or(ContractAddressError::NoneApiVersion)?
            .to_owned()
            .into(),
        n_external_functions: Felt252::from(external_functions.len()).into(),
        external_functions,
        n_l1_handlers: Felt252::from(l1_handlers.len()).into(),
        l1_handlers,
        n_constructors: Felt252::from(constructors.len()).into(),
        constructors,
        n_builtins: Felt252::from(builtin_list.len()).into(),
        builtin_list: builtin_list
            .iter()
            .map(|builtin| {
                Felt252::from_bytes_be(
                    builtin
                        .name()
                        .to_ascii_lowercase()
                        .strip_suffix("_builtin")
                        .unwrap()
                        .as_bytes(),
                )
                .into()
            })
            .collect::<Vec<MaybeRelocatable>>(),
        hinted_class_hash: compute_hinted_class_hash(contract_class).into(),
        bytecode_length: Felt252::from(contract_class_data.len()).into(),
        bytecode_ptr: contract_class_data,
    })
}

#[derive(Debug)]
struct DeprecatedCompiledClass {
    compiled_class_version: MaybeRelocatable,
    n_external_functions: MaybeRelocatable,
    external_functions: Vec<ContractEntryPoint>,
    n_l1_handlers: MaybeRelocatable,
    l1_handlers: Vec<ContractEntryPoint>,
    n_constructors: MaybeRelocatable,
    constructors: Vec<ContractEntryPoint>,
    n_builtins: MaybeRelocatable,
    builtin_list: Vec<MaybeRelocatable>,
    hinted_class_hash: MaybeRelocatable,
    bytecode_length: MaybeRelocatable,
    bytecode_ptr: Vec<MaybeRelocatable>,
}

fn flat_into_maybe_relocs(contract_entrypoints: Vec<ContractEntryPoint>) -> Vec<MaybeRelocatable> {
    contract_entrypoints
        .iter()
        .flat_map::<Vec<MaybeRelocatable>, _>(|contract_entrypoint| contract_entrypoint.into())
        .collect::<Vec<MaybeRelocatable>>()
}

impl From<DeprecatedCompiledClass> for CairoArg {
    fn from(contract_class: DeprecatedCompiledClass) -> Self {
        let external_functions_flatted = flat_into_maybe_relocs(contract_class.external_functions);
        let l1_handlers_flatted = flat_into_maybe_relocs(contract_class.l1_handlers);
        let constructors_flatted = flat_into_maybe_relocs(contract_class.constructors);

        let result = vec![
            CairoArg::Single(contract_class.compiled_class_version),
            CairoArg::Single(contract_class.n_external_functions),
            CairoArg::Array(external_functions_flatted),
            CairoArg::Single(contract_class.n_l1_handlers),
            CairoArg::Array(l1_handlers_flatted),
            CairoArg::Single(contract_class.n_constructors),
            CairoArg::Array(constructors_flatted),
            CairoArg::Single(contract_class.n_builtins),
            CairoArg::Array(contract_class.builtin_list),
            CairoArg::Single(contract_class.hinted_class_hash),
            CairoArg::Single(contract_class.bytecode_length),
            CairoArg::Array(contract_class.bytecode_ptr),
        ];
        CairoArg::Composed(result)
    }
}

// TODO: Maybe this could be hard-coded (to avoid returning a result)?
pub fn compute_deprecated_class_hash(
    contract_class: &ContractClass,
) -> Result<Felt252, ContractAddressError> {
    // Since we are not using a cache, this function replace compute_class_hash_inner.
    let hash_calculation_program = HASH_CALCULATION_PROGRAM.clone();

    let contract_class_struct = &get_contract_class_struct(
        hash_calculation_program
            .get_identifier("__main__.DEPRECATED_COMPILED_CLASS_VERSION")
            .ok_or(ContractAddressError::MissingIdentifier(
                "__main__.DEPRECATED_COMPILED_CLASS_VERSION".to_string(),
            ))?,
        contract_class,
    )?
    .into();

    let mut vm = VirtualMachine::new(false);
    let mut runner = CairoRunner::new(&hash_calculation_program, "all_cairo", false)?;
    runner.initialize_function_runner(&mut vm, false)?;
    let mut hint_processor = BuiltinHintProcessor::new_empty();

    let hash_runner = vm
        .get_builtin_runners()
        .iter()
        .find(|x| matches!(x, BuiltinRunner::Hash(_)))
        .unwrap();
    let hash_base = MaybeRelocatable::from((hash_runner.base() as isize, 0));

    let entrypoint = hash_calculation_program
        .get_identifier("__main__.deprecated_compiled_class_hash")
        .unwrap()
        .pc
        .unwrap();

    runner.run_from_entrypoint(
        entrypoint,
        &[&hash_base.into(), contract_class_struct],
        true,
        None,
        &mut vm,
        &mut hint_processor,
    )?;

    match vm.get_return_values(2)?.get(1) {
        Some(MaybeRelocatable::Int(felt)) => Ok(felt.clone()),
        _ => Err(ContractAddressError::IndexOutOfRange),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use cairo_vm::felt::Felt252;
    use coverage_helper::test;
    use num_traits::Num;

    #[test]
    fn test_starknet_keccak() {
        let data: &[u8] = "hello".as_bytes();

        // This expected output is the result of calling the python version in cairo-lang of the function.
        // starknet_keccak("hello".encode())
        let expected_result = Felt252::from_str_radix(
            "245588857976802048747271734601661359235654411526357843137188188665016085192",
            10,
        )
        .unwrap();
        let result = starknet_keccak(data);

        assert_eq!(expected_result, result);
    }

    #[test]
    fn test_get_contract_entrypoints() {
        let mut entry_points_by_type = HashMap::new();
        entry_points_by_type.insert(
            EntryPointType::Constructor,
            vec![ContractEntryPoint {
                selector: 1.into(),
                offset: 2,
            }],
        );
        let contract_class = ContractClass {
            program: HASH_CALCULATION_PROGRAM.clone(),
            entry_points_by_type,
            abi: None,
        };

        assert_eq!(
            get_contract_entry_points(&contract_class, &EntryPointType::Constructor).unwrap(),
            vec![ContractEntryPoint {
                selector: 1.into(),
                offset: 2
            }]
        );
        assert_matches!(
            get_contract_entry_points(&contract_class, &EntryPointType::External),
            Err(ContractAddressError::NoneExistingEntryPointType)
        );
    }

    #[test]
    fn test_compute_class_hash() {
        let mut entry_points_by_type = HashMap::new();
        entry_points_by_type.insert(
            EntryPointType::Constructor,
            vec![ContractEntryPoint {
                selector: 3.into(),
                offset: 2,
            }],
        );
        entry_points_by_type.insert(
            EntryPointType::L1Handler,
            vec![ContractEntryPoint {
                selector: 4.into(),
                offset: 2,
            }],
        );
        entry_points_by_type.insert(
            EntryPointType::External,
            vec![ContractEntryPoint {
                selector: 5.into(),
                offset: 2,
            }],
        );
        let contract_class = ContractClass {
            program: HASH_CALCULATION_PROGRAM.clone(),
            entry_points_by_type,
            abi: None,
        };
        assert_eq!(
            compute_deprecated_class_hash(&contract_class).unwrap(),
            Felt252::from_str_radix(
                "1809635095607326950459993008040437939724930328662161791121345395618950656878",
                10
            )
            .unwrap()
        );
    }

    #[test]
    fn test_compute_hinted_class_hash() {
        let mut entry_points_by_type = HashMap::new();
        entry_points_by_type.insert(
            EntryPointType::Constructor,
            vec![ContractEntryPoint {
                selector: 1.into(),
                offset: 12,
            }],
        );
        entry_points_by_type.insert(
            EntryPointType::L1Handler,
            vec![ContractEntryPoint {
                selector: 2.into(),
                offset: 12,
            }],
        );
        entry_points_by_type.insert(
            EntryPointType::External,
            vec![ContractEntryPoint {
                selector: 3.into(),
                offset: 12,
            }],
        );
        let contract_class = ContractClass {
            program: HASH_CALCULATION_PROGRAM.clone(),
            entry_points_by_type,
            abi: None,
        };

        assert_eq!(
            compute_hinted_class_hash(&contract_class),
            Felt252::from_str_radix(
                "1703103364832599665802491695999915073351807236114175062140703903952998591438",
                10
            )
            .unwrap()
        );
    }
}
