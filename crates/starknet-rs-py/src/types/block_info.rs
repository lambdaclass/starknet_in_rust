use cairo_rs::felt::Felt252;
use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*, types::PyType};
use starknet_rs::{
    business_logic::state::state_api_objects::BlockInfo, definitions::constants::DEFAULT_GAS_PRICE,
    utils::Address,
};

#[pyclass(name = "BlockInfo")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyBlockInfo {
    inner: BlockInfo,
}

#[pymethods]
impl PyBlockInfo {
    #[new]
    fn new(
        block_number: u64,
        block_timestamp: u64,
        gas_price: u64,
        sequencer_address: BigUint,
        starknet_version: String,
    ) -> Self {
        let address = Address(Felt252::from(sequencer_address));
        let inner = BlockInfo {
            block_number,
            block_timestamp,
            gas_price,
            sequencer_address: address,
            starknet_version,
        };
        Self { inner }
    }

    /// Returns an empty BlockInfo object; i.e., the one before the first in the chain.
    #[classmethod]
    fn empty(_cls: &PyType, address: BigUint) -> PyBlockInfo {
        let inner = BlockInfo::empty(Address(Felt252::from(address)));
        Self { inner }
    }

    /// Returns a BlockInfo object with default gas_price.
    #[classmethod]
    fn create_for_testing(
        _cls: &PyType,
        block_number: u64,
        block_timestamp: u64,
        gas_price: Option<u64>,
    ) -> PyBlockInfo {
        let gas_price = gas_price.unwrap_or(DEFAULT_GAS_PRICE);
        let inner = BlockInfo {
            block_number,
            block_timestamp,
            gas_price,
            ..Default::default()
        };
        Self { inner }
    }

    /// Validates that next_block_info is a legal progress of self.
    fn validate_legal_progress(&self, next_block_info: &PyBlockInfo) -> PyResult<()> {
        self.inner
            .validate_legal_progress(&next_block_info.inner)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    #[getter]
    fn block_number(&self) -> u64 {
        self.inner.block_number
    }

    #[getter]
    fn block_timestamp(&self) -> u64 {
        self.inner.block_timestamp
    }

    #[getter]
    fn gas_price(&self) -> u64 {
        self.inner.gas_price
    }

    #[getter]
    fn sequencer_address(&self) -> BigUint {
        self.inner.sequencer_address.0.to_biguint()
    }

    #[getter]
    fn starknet_version(&self) -> String {
        self.inner.starknet_version.clone()
    }
}

impl From<BlockInfo> for PyBlockInfo {
    fn from(inner: BlockInfo) -> Self {
        Self { inner }
    }
}

impl From<PyBlockInfo> for BlockInfo {
    fn from(py_value: PyBlockInfo) -> Self {
        py_value.inner
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pyo3::{types::IntoPyDict, IntoPy, PyTypeInfo, Python};

    #[test]
    fn validate_legal_progress() {
        Python::with_gil(|py| {
            let cls = <PyBlockInfo as PyTypeInfo>::type_object(py);
            let block_info = PyBlockInfo::create_for_testing(cls, 1, 5, None).into_py(py);
            let next_block_info = PyBlockInfo::create_for_testing(cls, 2, 13, None).into_py(py);

            let locals = [
                ("block_info", block_info),
                ("next_block_info", next_block_info),
            ]
            .into_py_dict(py);

            let code = "block_info.validate_legal_progress(next_block_info)";

            assert!(py.run(code, None, Some(locals)).is_ok());
        });
    }
}
