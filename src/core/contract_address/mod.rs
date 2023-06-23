pub mod v2;

use std::{borrow::Cow, collections::BTreeMap};

/// Contains functionality for computing class hashes for deprecated Declare transactions
/// (ie, declarations that do not correspond to Cairo 1 contracts)
use crate::{
    core::errors::contract_address_errors::ContractAddressError,
    hash_utils::compute_hash_on_elements,
    services::api::contract_classes::deprecated_contract_class::ContractClass,
};
use cairo_vm::felt::Felt252;

use num_traits::Zero;
use serde::Serialize;
// use serde_json::json;
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

fn add_extra_space_to_cairo_named_tuples(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(v) => walk_array(v),
        serde_json::Value::Object(m) => walk_map(m),
        _ => {}
    }
}

fn walk_array(array: &mut [serde_json::Value]) {
    for v in array.iter_mut() {
        add_extra_space_to_cairo_named_tuples(v);
    }
}

fn walk_map(object: &mut serde_json::Map<String, serde_json::Value>) {
    for (k, v) in object.iter_mut() {
        match v {
            serde_json::Value::String(s) => {
                let new_value = add_extra_space_to_named_tuple_type_definition(k, s);
                if new_value.as_ref() != s {
                    *v = serde_json::Value::String(new_value.into());
                }
            }
            _ => add_extra_space_to_cairo_named_tuples(v),
        }
    }
}

fn add_extra_space_to_named_tuple_type_definition<'a>(
    key: &str,
    value: &'a str,
) -> std::borrow::Cow<'a, str> {
    use std::borrow::Cow::*;
    match key {
        "cairo_type" | "value" => Owned(add_extra_space_before_colon(value)),
        _ => Borrowed(value),
    }
}

fn add_extra_space_before_colon(v: &str) -> String {
    // This is required because if we receive an already correct ` : `, we will still
    // "repair" it to `  : ` which we then fix at the end.
    v.replace(": ", " : ").replace("  :", " :")
}
#[derive(Default)]
struct KeccakWriter(sha3::Keccak256);

impl std::io::Write for KeccakWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // noop is fine, we'll finalize after the write phase
        Ok(())
    }
}

/// Starkware doesn't use compact formatting for JSON but default python formatting.
/// This is required to hash to the same value after sorted serialization.
struct PythonDefaultFormatter;

impl serde_json::ser::Formatter for PythonDefaultFormatter {
    fn begin_array_value<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_key<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        writer.write_all(b": ")
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CairoContractDefinition<'a> {
    /// Contract ABI, which has no schema definition.
    pub abi: serde_json::Value,

    /// Main program definition.
    #[serde(borrow)]
    pub program: CairoProgramToHash<'a>,

    /// The contract entry points.
    ///
    /// These are left out of the re-serialized version with the ordering requirement to a
    /// Keccak256 hash.
    #[serde(skip_serializing)]
    pub entry_points_by_type: serde_json::Value,
}

// It's important that this is ordered alphabetically because the fields need to be in
// sorted order for the keccak hashed representation.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CairoProgramToHash<'a> {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub attributes: Vec<serde_json::Value>,

    #[serde(borrow)]
    pub builtins: Vec<Cow<'a, str>>,

    // Added in Starknet 0.10, so we have to handle this not being present.
    #[serde(borrow, skip_serializing_if = "Option::is_none")]
    pub compiler_version: Option<Cow<'a, str>>,

    #[serde(borrow)]
    pub data: Vec<Cow<'a, str>>,

    #[serde(borrow)]
    pub debug_info: Option<&'a serde_json::value::RawValue>,

    // Important that this is ordered by the numeric keys, not lexicographically
    pub hints: BTreeMap<u64, Vec<serde_json::Value>>,

    pub identifiers: serde_json::Value,

    #[serde(borrow)]
    pub main_scope: Cow<'a, str>,

    // Unlike most other integers, this one is hex string. We don't need to interpret it,
    // it just needs to be part of the hashed output.
    #[serde(borrow)]
    pub prime: Cow<'a, str>,

    pub reference_manager: serde_json::Value,
}

/// Computes the hash of the contract class, including hints.
/// We are not supporting backward compatibility now.
fn compute_hinted_class_hash(contract_class: &ContractClass) -> Felt252 {
    println!("program: {:?}", contract_class.program_json["program"]);
    let program_as_string = contract_class.program_json.to_string();
    let mut cairo_program_hash: CairoContractDefinition = serde_json::from_str(&program_as_string).unwrap();

    cairo_program_hash
    .program
    .attributes
    .iter_mut()
    .try_for_each(|attr| -> anyhow::Result<()> {
        let vals = attr
            .as_object_mut()
            .unwrap();

        match vals.get_mut("accessible_scopes") {
            Some(serde_json::Value::Array(array)) => {
                if array.is_empty() {
                    vals.remove("accessible_scopes");
                }
            }
            Some(_other) => {
                anyhow::bail!(
                    r#"A program's attribute["accessible_scopes"] was not an array type."#
                );
            }
            None => {}
        }
        // We don't know what this type is supposed to be, but if its missing it is null.
        if let Some(serde_json::Value::Null) = vals.get_mut("flow_tracking_data") {
            vals.remove("flow_tracking_data");
        }

        Ok(())
    }).unwrap();
    // Handle a backwards compatibility hack which is required if compiler_version is not present.
    // See `insert_space` for more details.
    if cairo_program_hash.program.compiler_version.is_none() {
        add_extra_space_to_cairo_named_tuples(&mut cairo_program_hash.program.identifiers);
        add_extra_space_to_cairo_named_tuples(&mut cairo_program_hash.program.reference_manager);
    }
    let mut ser =
        serde_json::Serializer::with_formatter(KeccakWriter::default(), PythonDefaultFormatter);

    cairo_program_hash
        .serialize(&mut ser)
        .unwrap();

    let KeccakWriter(hash) = ser.into_inner();
    let res = truncated_keccak(<[u8; 32]>::from(hash.finalize()));
    println!("hinted result: {:?}", res);
    res
    // let result = starknet_keccak(&serde_json::to_vec(&cairo_program_hash).unwrap());
    // println!("hinted: {:?}", result);
    // result
    // let keccak_input =
    //     r#"{"abi": contract_class.abi, "program": contract_class.program}"#;
    // let serialized = unicode_encode(keccak_input); 
    // starknet_keccak(serialized.as_bytes())
}

pub(crate) fn truncated_keccak(mut plain: [u8; 32]) -> Felt252 {
    // python code masks with (2**250 - 1) which starts 0x03 and is followed by 31 0xff in be
    // truncation is needed not to overflow the field element.
    plain[0] &= 0x03;
    Felt252::from_bytes_be(&plain)
}

// Temporary hack here because Python only emits ASCII to JSON.
#[allow(unused)]
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
    mut contract_class: &ContractClass,
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

    let hinted_class_hash = compute_hinted_class_hash(&mut contract_class);

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
    use std::{collections::HashMap, fs, str::FromStr};

    use super::*;
    use cairo_vm::{felt::Felt252, types::program::Program};
    use coverage_helper::test;
    use num_traits::Num;
    use serde_json::json;
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
            program_json: contract_str.into(),
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

        let mut contract_class = ContractClass {
            program_json: contract_str.into(),
            program: hash_calculation_program,
            entry_points_by_type,
            abi: None,
        };
        assert_eq!(
            compute_deprecated_class_hash(&mut contract_class).unwrap(),
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

        let mut contract_class = ContractClass {
            program_json: contract_str.into(),
            program: hash_calculation_program,
            entry_points_by_type,
            abi: None,
        };

        assert_eq!(
            compute_hinted_class_hash(&mut contract_class),
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
        let mut contract_class = ContractClass {
            program_json: contract_str.into(),
            program: parsed_contract_class.program,
            entry_points_by_type: parsed_contract_class.entry_points_by_type,
            abi: parsed_contract_class.abi,
        };
        assert_eq!(
            compute_hinted_class_hash(&mut contract_class),
            Felt252::from_str_radix(
                "1703103364832599665802491695999915073351807236114175062140703903952998591438",
                10
            )
            .unwrap()
        );
    }

    #[test]
    fn test_compute_class_hash_xxx() {
        let contract_str = fs::read_to_string("failing_class.json").unwrap();
        let parsed_contract_class = ParsedContractClass::try_from(contract_str.as_str()).unwrap();
        let mut contract_class = ContractClass {
            program_json: serde_json::Value::from_str(&contract_str).unwrap(),
            program: parsed_contract_class.program,
            entry_points_by_type: parsed_contract_class.entry_points_by_type,
            abi: parsed_contract_class.abi,
        };

        assert_eq!(
            compute_deprecated_class_hash(&mut contract_class).unwrap(),
            Felt252::from_str_radix(
                "1354433237b0039baa138bf95b98fe4a8ae3df7ac4fd4d4845f0b41cd11bec4",
                16
            )
            .unwrap()
        );
    }
}
