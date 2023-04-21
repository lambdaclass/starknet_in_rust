use cairo_vm::felt::Felt252;
use num_bigint::BigUint;
use pyo3::{exceptions::PyValueError, prelude::*};
use starknet_rs::business_logic::{
    fact_state::in_memory_state_reader::InMemoryStateReader, state::cached_state::CachedState,
    transaction::objects::internal_invoke_function::InternalInvokeFunction,
};

use crate::{
    cached_state::PyCachedState,
    types::{
        general_config::PyStarknetGeneralConfig,
        transaction_execution_info::PyTransactionExecutionInfo,
    },
};

#[pyclass(subclass)]
#[pyo3(name = "InternalInvokeFunction")]
pub struct PyInternalInvokeFunction {
    inner: InternalInvokeFunction,
}

#[pymethods]
impl PyInternalInvokeFunction {
    #[getter]
    fn hash_value(&self) -> BigUint {
        self.inner.hash_value().to_biguint()
    }

    #[getter]
    fn signature(&self) -> Vec<BigUint> {
        self.inner
            .signature()
            .iter()
            .map(Felt252::to_biguint)
            .collect()
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
