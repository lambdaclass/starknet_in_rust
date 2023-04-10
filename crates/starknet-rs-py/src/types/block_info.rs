use cairo_felt::Felt252;
use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*, types::PyType};
use starknet_rs::{business_logic::state::state_api_objects::BlockInfo, utils::Address};

#[pyclass]
#[pyo3(name = "BlockInfo")]
#[derive(Debug)]
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
    fn create_for_testing(_cls: &PyType, block_number: u64, block_timestamp: u64) -> PyBlockInfo {
        let inner = BlockInfo {
            block_number,
            block_timestamp,
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

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::{types::IntoPyDict, IntoPy, PyTypeInfo, Python};

    #[test]
    fn validate_legal_progress() {
        Python::with_gil(|py| {
            let cls = <PyBlockInfo as PyTypeInfo>::type_object(py);
            let block_info = PyBlockInfo::create_for_testing(cls, 1, 5).into_py(py);
            let next_block_info = PyBlockInfo::create_for_testing(cls, 2, 13).into_py(py);

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
