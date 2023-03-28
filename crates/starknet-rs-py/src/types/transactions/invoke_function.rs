use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::business_logic::transaction::objects::internal_invoke_function::InternalInvokeFunction;

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
