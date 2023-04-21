use cairo_vm::felt::Felt252;
use num_bigint::BigUint;
use pyo3::{exceptions::PyValueError, prelude::*};
use starknet_rs::{
    business_logic::{
        fact_state::in_memory_state_reader::InMemoryStateReader, state::cached_state::CachedState,
        transaction::objects::internal_deploy::InternalDeploy,
    },
    definitions::transaction_type::TransactionType,
    utils::{Address, ClassHash},
};

use crate::{
    cached_state::PyCachedState,
    types::{
        general_config::PyStarknetGeneralConfig,
        transaction_execution_info::PyTransactionExecutionInfo,
    },
};

#[pyclass(subclass)]
#[pyo3(name = "InternalDeploy")]
pub struct PyInternalDeploy {
    inner: InternalDeploy,
}

#[pymethods]
impl PyInternalDeploy {
    #[new]
    fn new(
        contract_address: BigUint,
        contract_hash: ClassHash,
        contract_address_salt: BigUint,
        hash_value: BigUint,
        version: u64,
        constructor_calldata: Vec<BigUint>,
    ) -> Self {
        let contract_address = Address(Felt252::from(contract_address));
        let contract_address_salt = Address(Felt252::from(contract_address_salt));
        let constructor_calldata = constructor_calldata
            .into_iter()
            .map(Felt252::from)
            .collect();
        let hash_value = Felt252::from(hash_value);

        let inner = InternalDeploy {
            hash_value,
            version,
            contract_address,
            contract_address_salt,
            contract_hash,
            constructor_calldata,
            tx_type: TransactionType::Deploy,
        };

        Self { inner }
    }

    #[getter]
    fn class_hash(&self) -> ClassHash {
        self.inner.class_hash()
    }

    #[getter]
    fn hash_value(&self) -> BigUint {
        self.inner.hash_value.to_biguint()
    }

    #[getter]
    fn contract_address(&self) -> BigUint {
        self.inner.contract_address.0.to_biguint()
    }

    fn apply_state_updates(
        &self,
        state: &mut PyCachedState,
        general_config: &PyStarknetGeneralConfig,
    ) -> PyResult<PyTransactionExecutionInfo> {
        let state: &mut CachedState<InMemoryStateReader> = state.into();
        match self.inner.execute(state, general_config.into()) {
            Ok(res) => Ok(res.into()),
            Err(err) => Err(PyValueError::new_err(err.to_string())),
        }
    }
}
