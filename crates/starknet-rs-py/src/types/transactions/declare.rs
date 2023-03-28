use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::{
    business_logic::transaction::objects::internal_declare::InternalDeclare,
    definitions::{
        constants::VALIDATE_DECLARE_ENTRY_POINT_SELECTOR, transaction_type::TransactionType,
    },
    services::api::contract_class::ContractClass,
    utils::{Address, ClassHash},
};

#[pyclass]
pub struct PyInternalDeclare {
    inner: InternalDeclare,
}

#[pymethods]
impl PyInternalDeclare {
    #[new]
    fn new(
        hash_value: BigUint,
        version: u64,
        max_fee: u64,
        signature: Vec<BigUint>,
        nonce: BigUint,
        class_hash: ClassHash,
        sender_address: BigUint,
    ) -> Self {
        let sender_address = Address(Felt252::from(sender_address));
        let signature = signature.into_iter().map(Felt252::from).collect();
        let nonce = Felt252::from(nonce);
        let hash_value = Felt252::from(hash_value);
        let contract_class =
            ContractClass::new(Default::default(), Default::default(), None).unwrap();

        let inner = InternalDeclare {
            class_hash,
            sender_address,
            tx_type: TransactionType::Declare,
            validate_entry_point_selector: VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone(),
            version,
            max_fee,
            signature,
            nonce,
            hash_value,
            contract_class,
        };

        Self { inner }
    }

    #[getter]
    fn class_hash(&self) -> ClassHash {
        self.inner.class_hash
    }

    #[getter]
    fn hash_value(&self) -> BigUint {
        self.inner.hash_value.to_biguint()
    }

    #[getter]
    fn contract_address(&self) -> BigUint {
        self.inner.sender_address.0.to_biguint()
    }

    #[getter]
    fn signature(&self) -> Vec<BigUint> {
        self.inner
            .signature
            .iter()
            .map(Felt252::to_biguint)
            .collect()
    }

    // fn apply_state_updates(
    //     &self,
    //     state: PyStarknetState,
    //     general_config: PyStarknetGeneralConfig,
    // ) -> PyResult<PyTransactionExecutionInfo> {
    //     // TODO: check if this is really equivalent
    //     self.inner
    //         .execute(state, general_config.into())
    //         .map_err(|e| PyValueError::new_err(e.to_string()))
    // }
}
