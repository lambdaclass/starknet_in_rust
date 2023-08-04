use crate::core::errors::contract_address_errors::ContractAddressError;
use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;
use cairo_lang_starknet::casm_contract_class::{CasmContractClass, CasmContractEntryPoint};
use cairo_vm::felt::Felt252;
use starknet_crypto::{poseidon_hash_many, FieldElement};

const CONTRACT_CLASS_VERSION: &[u8] = b"COMPILED_CLASS_V1";

fn get_contract_entry_points_hashed(
    contract_class: &CasmContractClass,
    entry_point_type: &EntryPointType,
) -> Result<FieldElement, ContractAddressError> {
    let contract_entry_points = get_contract_entry_points(contract_class, entry_point_type);

    // for each entry_point, we need to store 3 FieldElements: [selector, offset, poseidon_hash_many(builtin_list)].
    let mut entry_points_flatted = Vec::with_capacity(contract_entry_points.len() * 3);

    for entry_point in contract_entry_points {
        entry_points_flatted.push(
            // fix this conversion later
            FieldElement::from_bytes_be(&Felt252::from(entry_point.selector).to_be_bytes())
                .map_err(|_err| {
                    ContractAddressError::Cast("Felt252".to_string(), "FieldElement".to_string())
                })?,
        );
        entry_points_flatted.push(FieldElement::from(entry_point.offset));
        let builtins_flatted = entry_point
            .builtins
            .iter()
            .map(|builtin| FieldElement::from_byte_slice_be(builtin.as_bytes()))
            .collect::<Result<Vec<FieldElement>, _>>()
            .map_err(|_err| {
                ContractAddressError::Cast("Felt252".to_string(), "FieldElement".to_string())
            })?;
        entry_points_flatted.push(poseidon_hash_many(&builtins_flatted));
    }

    Ok(poseidon_hash_many(&entry_points_flatted))
}

pub fn compute_casm_class_hash(
    contract_class: &CasmContractClass,
) -> Result<Felt252, ContractAddressError> {
    let api_version =
        FieldElement::from_bytes_be(&Felt252::from_bytes_be(CONTRACT_CLASS_VERSION).to_be_bytes())
            .map_err(|_err| {
                ContractAddressError::Cast("Felt252".to_string(), "FieldElement".to_string())
            })?;

    // Entrypoints by type, hashed.
    let external_functions =
        get_contract_entry_points_hashed(contract_class, &EntryPointType::External)?;
    let l1_handlers = get_contract_entry_points_hashed(contract_class, &EntryPointType::L1Handler)?;
    let constructors =
        get_contract_entry_points_hashed(contract_class, &EntryPointType::Constructor)?;

    let mut casm_program_vector = Vec::with_capacity(contract_class.bytecode.len());
    for number in &contract_class.bytecode {
        casm_program_vector.push(
            FieldElement::from_bytes_be(&Felt252::from(number.value.clone()).to_be_bytes())
                .map_err(|_err| {
                    ContractAddressError::Cast("Felt252".to_string(), "FieldElement".to_string())
                })?,
        );
    }

    // Hash casm program.
    let casm_program_ptr = poseidon_hash_many(&casm_program_vector);

    let flatted_contract_class = vec![
        api_version,
        external_functions,
        l1_handlers,
        constructors,
        casm_program_ptr,
    ];

    Ok(Felt252::from_bytes_be(
        &poseidon_hash_many(&flatted_contract_class).to_bytes_be(),
    ))
}

fn get_contract_entry_points(
    contract_class: &CasmContractClass,
    entry_point_type: &EntryPointType,
) -> Vec<CasmContractEntryPoint> {
    match entry_point_type {
        EntryPointType::Constructor => contract_class.entry_points_by_type.constructor.clone(),
        EntryPointType::External => contract_class.entry_points_by_type.external.clone(),
        EntryPointType::L1Handler => contract_class.entry_points_by_type.l1_handler.clone(),
    }
}

#[cfg(test)]
mod tests {
    /// THE VALUES IN THIS TESTS WERE TAKEN FROM THE CONTRACTS IN THE STARKNET_PROGRAMS FOLDER.
    /// AND WE USE A [TOOL FOUND IN CAIRO-LANG](https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/starknet/cli/compiled_class_hash.py)
    /// TO GET THE RIGHT HASH VALUE.
    use std::{fs::File, io::BufReader};

    use super::*;
    use cairo_vm::felt::felt_str;
    use coverage_helper::test;

    #[test]
    fn test_compute_casm_class_hash_contract_a() {
        // Open the file in read-only mode with buffer.
        let file;
        let expected_result;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            file = File::open("starknet_programs/cairo2/contract_a.casm").unwrap();
            expected_result = felt_str!(
                "321aadcf42b0a4ad905616598d16c42fa9b87c812dc398e49b57bf77930629f",
                16
            );
        }
        #[cfg(feature = "cairo_1_tests")]
        {
            file = File::open("starknet_programs/cairo1/contract_a.casm").unwrap();
            expected_result = felt_str!(
                "3a4f00bf75ba3b9230a94f104c7a4605a1901c4bd475beb59eeeeb7aceb9795",
                16
            );
        }
        let reader = BufReader::new(file);

        // Read the JSON contents of the file as an instance of `CasmContractClass`.
        let contract_class: CasmContractClass = serde_json::from_reader(reader).unwrap();

        assert_eq!(
            compute_casm_class_hash(&contract_class).unwrap(),
            expected_result
        );
    }

    #[test]
    fn test_compute_casm_class_hash_deploy() {
        // Open the file in read-only mode with buffer.
        let file;
        let expected_result;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            file = File::open("starknet_programs/cairo2/deploy.casm").unwrap();
            expected_result = felt_str!(
                "53ad3bfb13f39cf1a9940108be4f9c6a8d9cc48a59d5f9b3c73432f877f8cf0",
                16
            );
        }

        #[cfg(feature = "cairo_1_tests")]
        {
            file = File::open("starknet_programs/cairo1/deploy.casm").unwrap();
            expected_result = felt_str!(
                "3bd56f1c3c1c595ac2ee6d07bdedc027d09df56235e20374649f0b3535c1f15",
                16
            );
        }
        let reader = BufReader::new(file);

        // Read the JSON contents of the file as an instance of `CasmContractClass`.
        let contract_class: CasmContractClass = serde_json::from_reader(reader).unwrap();

        assert_eq!(
            compute_casm_class_hash(&contract_class).unwrap(),
            expected_result
        );
    }

    #[test]
    fn test_compute_casm_class_hash_fibonacci() {
        // Open the file in read-only mode with buffer.
        let file;
        let expected_result;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            file = File::open("starknet_programs/cairo2/fibonacci.casm").unwrap();
            expected_result = felt_str!(
                "6638ce6c9bf336d1781a388668fa2206d928df5d1fa6b92e4cb41004c7e3f89",
                16
            );
        }

        #[cfg(feature = "cairo_1_tests")]
        {
            file = File::open("starknet_programs/cairo1/fibonacci.casm").unwrap();
            expected_result = felt_str!(
                "44f12e6e59232e9909d7428b913b3cc8d9059458e5027740a3ccdbdc4b1ffd2",
                16
            );
        }
        let reader = BufReader::new(file);

        // Read the JSON contents of the file as an instance of `CasmContractClass`.
        let contract_class: CasmContractClass = serde_json::from_reader(reader).unwrap();

        assert_eq!(
            compute_casm_class_hash(&contract_class).unwrap(),
            expected_result
        );
    }

    #[test]
    fn test_compute_casm_class_hash_factorial() {
        // Open the file in read-only mode with buffer.
        let file;
        let expected_result;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            file = File::open("starknet_programs/cairo2/factorial.casm").unwrap();
            expected_result = felt_str!(
                "7c48d040ceb3183837a0aff2adf33d879f790e202eb2c4b8622005c12252641",
                16
            );
        }

        #[cfg(feature = "cairo_1_tests")]
        {
            file = File::open("starknet_programs/cairo1/factorial.casm").unwrap();
            expected_result = felt_str!(
                "189a9b8b852aedbb225aa28dce9cfc3133145dd623e2d2ca5e962b7d4e61e15",
                16
            );
        }
        let reader = BufReader::new(file);

        // Read the JSON contents of the file as an instance of `CasmContractClass`.
        let contract_class: CasmContractClass = serde_json::from_reader(reader).unwrap();

        assert_eq!(
            compute_casm_class_hash(&contract_class).unwrap(),
            expected_result
        );
    }

    #[test]
    fn test_compute_casm_class_hash_emit_event() {
        // Open the file in read-only mode with buffer.
        let file;
        let expected_result;
        #[cfg(not(feature = "cairo_1_tests"))]
        {
            file = File::open("starknet_programs/cairo2/emit_event.casm").unwrap();
            expected_result = felt_str!(
                "3010533bd60cb0e70ac1bf776e171713f0e5229a084989d3894c171c160ace2",
                16
            );
        }

        #[cfg(feature = "cairo_1_tests")]
        {
            file = File::open("starknet_programs/cairo1/emit_event.casm").unwrap();
            expected_result = felt_str!(
                "3335fe731ceda1116eda8bbc2e282953ce54618309ad474189e627c59328fff",
                16
            );
        }
        let reader = BufReader::new(file);

        // Read the JSON contents of the file as an instance of `CasmContractClass`.
        let contract_class: CasmContractClass = serde_json::from_reader(reader).unwrap();

        assert_eq!(
            compute_casm_class_hash(&contract_class).unwrap(),
            expected_result
        );
    }

    #[test]
    fn test_declare_tx_class_hash() {
        let file = File::open("starknet_programs/cairo2/events.casm").unwrap();
        let reader = BufReader::new(file);

        let contract_class: CasmContractClass = serde_json::from_reader(reader).unwrap();

        // this is the compiled_class_hash from: https://alpha4.starknet.io/feeder_gateway/get_transaction?transactionHash=0x01b852f1fe2b13db21a44f8884bc4b7760dc277bb3820b970dba929860275617
        let expected_result = felt_str!(
            "2011836827876139258613930428521012424481847645471980617287552173098289225455"
        );

        assert_eq!(
            compute_casm_class_hash(&contract_class).unwrap(),
            expected_result
        )
    }
}
