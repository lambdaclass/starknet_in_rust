use num_bigint::BigUint;
use pyo3::prelude::*;
use starknet_rs::{
    business_logic::transaction::objects::internal_deploy_account::InternalDeployAccount,
    utils::ClassHash,
};

#[pyclass(subclass)]
#[pyo3(name = "InternalDeployAccount")]
pub struct PyInternalDeployAccount {
    inner: InternalDeployAccount,
}

#[pymethods]
impl PyInternalDeployAccount {
    #[getter]
    fn class_hash(&self) -> ClassHash {
        *self.inner.class_hash()
    }

    #[getter]
    fn signature(&self) -> Vec<BigUint> {
        Default::default()
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
