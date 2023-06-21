pub mod v2;

/// Contains functionality for computing class hashes for deprecated Declare transactions
/// (ie, declarations that do not correspond to Cairo 1 contracts)
use crate::{
    core::errors::contract_address_errors::ContractAddressError,
    hash_utils::compute_hash_on_elements,
    services::api::contract_classes::deprecated_contract_class::ContractClass,
};
use cairo_vm::felt::Felt252;

use num_traits::Zero;
use sha3::{Digest, Keccak256};
use starknet_contract_class::{ContractEntryPoint, EntryPointType};

/// Instead of doing a Mask with 250 bits, we are only masking the most significant byte.
pub const MASK_3: u8 = 3;

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
        if entry_point.offset() > program_len {
            return Err(ContractAddressError::InvalidOffset(entry_point.offset()));
        }
    }
    Ok(entry_points.to_owned())
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
//     if len(dumped_program["attributes"]) == 0:
//     # Remove attributes field from raw dictionary, for hash backward compatibility of
//     # contracts deployed prior to adding this feature.
//     del dumped_program["attributes"]
// else:
//     # Remove accessible_scopes and flow_tracking_data fields from raw dictionary, for hash
//     # backward compatibility of contracts deployed prior to adding this feature.
//     for attr in dumped_program["attributes"]:
//         if len(attr["accessible_scopes"]) == 0:
//             del attr["accessible_scopes"]
//         if attr["flow_tracking_data"] is None:
//             del attr["flow_tracking_data"]
    let keccak_input =
        r#"{"abi": contract_class.abi, "program": contract_class.program}"#;
    let serialized = unicode_encode(keccak_input); 
    starknet_keccak(serialized.as_bytes())
}

    // Temporary hack here because Python only emits ASCII to JSON.
    fn unicode_encode(s: &str) -> String {
        use std::fmt::Write;

        let mut output = String::with_capacity(s.len());
        let mut buf = [0, 0];

        for c in s.chars() {
            if c.is_ascii() {
                output.push(c);
            } else {
                let buf = c.encode_utf16(&mut buf);
                for i in buf {
                    // Unwrapping should be safe here
                    write!(output, r"\u{:4x}", i).unwrap();
                }
            }
        }

        output
    }

fn get_contract_entry_points_hashed(
    contract_class: &ContractClass,
    entry_point_type: &EntryPointType,
) -> Result<Felt252, ContractAddressError> {
    Ok(compute_hash_on_elements(
        &get_contract_entry_points(contract_class, entry_point_type)?
            .iter()
            .flat_map(|contract_entry_point| {
                vec![
                    contract_entry_point.selector().clone(),
                    Felt252::from(contract_entry_point.offset()),
                ]
            })
            .collect::<Vec<Felt252>>(),
    )?)
}

pub fn compute_deprecated_class_hash(
    contract_class: &ContractClass,
) -> Result<Felt252, ContractAddressError> {
    // Deprecated API version.
    let api_version = Felt252::zero();

    // Entrypoints by type, hashed.
    let external_functions =
        get_contract_entry_points_hashed(contract_class, &EntryPointType::External)?;
    let l1_handlers = get_contract_entry_points_hashed(contract_class, &EntryPointType::L1Handler)?;
    let constructors =
        get_contract_entry_points_hashed(contract_class, &EntryPointType::Constructor)?;

    // Builtin list but with the "_builtin" suffix removed.
    // This could be Vec::with_capacity when using the latest version of cairo-vm which includes .builtins_len() method for Program.
    let mut builtin_list_vec = Vec::new();

    for builtin_name in contract_class.program().iter_builtins() {
        builtin_list_vec.push(Felt252::from_bytes_be(
            builtin_name
                .name()
                .strip_suffix("_builtin")
                .ok_or(ContractAddressError::BuiltinSuffix)?
                .as_bytes(),
        ));
    }

    let builtin_list = compute_hash_on_elements(&builtin_list_vec)?;

    let hinted_class_hash = compute_hinted_class_hash(contract_class);

    let mut bytecode_vector = Vec::new();

    for data in contract_class.program().iter_data() {
        bytecode_vector.push(
            data.get_int_ref()
                .ok_or(ContractAddressError::NoneIntMaybeRelocatable)?
                .clone(),
        );
    }

    let bytecode = compute_hash_on_elements(&bytecode_vector)?;

    let flatted_contract_class: Vec<Felt252> = vec![
        api_version,
        external_functions,
        l1_handlers,
        constructors,
        builtin_list,
        hinted_class_hash,
        bytecode,
    ];

    Ok(compute_hash_on_elements(&flatted_contract_class)?)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs};

    use super::*;
    use cairo_vm::{felt::Felt252, types::program::Program};
    use coverage_helper::test;
    use num_traits::Num;
    use starknet_contract_class::ParsedContractClass;

    const DEPRECATED_COMPILED_CLASS_CONTRACT: &str =
        "cairo_programs/deprecated_compiled_class.json";

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
        let contract_str = fs::read_to_string(DEPRECATED_COMPILED_CLASS_CONTRACT).unwrap();

        let hash_calculation_program: Program =
            Program::from_bytes(contract_str.as_bytes(), None).unwrap();

        let contract_class = ContractClass {
            program: hash_calculation_program,
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
        let contract_str = fs::read_to_string(DEPRECATED_COMPILED_CLASS_CONTRACT).unwrap();

        let hash_calculation_program: Program =
            Program::from_bytes(contract_str.as_bytes(), None).unwrap();

        let contract_class = ContractClass {
            program: hash_calculation_program,
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
        let contract_str = fs::read_to_string(DEPRECATED_COMPILED_CLASS_CONTRACT).unwrap();

        let hash_calculation_program: Program =
            Program::from_bytes(contract_str.as_bytes(), None).unwrap();

        let contract_class = ContractClass {
            program: hash_calculation_program,
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

    #[test]
    fn test_compute_hinted_class_hash_with_abi() {
        let contract_str = fs::read_to_string("starknet_programs/class_with_abi.json").unwrap();
        let parsed_contract_class = ParsedContractClass::try_from(contract_str.as_str()).unwrap();
        let contract_class = ContractClass {
            program: parsed_contract_class.program,
            entry_points_by_type: parsed_contract_class.entry_points_by_type,
            abi: parsed_contract_class.abi,
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

    #[test]
    fn test_compute_class_hash_xxx() {
        let contract_str = fs::read_to_string("starknet_programs/failing_class.json").unwrap();
        let parsed_contract_class = ParsedContractClass::try_from(contract_str.as_str()).unwrap();
        let contract_class = ContractClass {
            program: parsed_contract_class.program,
            entry_points_by_type: parsed_contract_class.entry_points_by_type,
            abi: parsed_contract_class.abi,
        };

        println!("contract_class: {:?}", contract_class);

        assert_eq!(
            compute_deprecated_class_hash(&contract_class).unwrap(),
            Felt252::from_str_radix(
                "1354433237b0039baa138bf95b98fe4a8ae3df7ac4fd4d4845f0b41cd11bec4",
                16
            )
            .unwrap()
        );
    }
}
