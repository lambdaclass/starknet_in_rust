use cairo_felt::Felt;
use num_bigint::BigUint;
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use starknet_rs::{
    business_logic::execution::objects::TransactionExecutionInfo,
    services::api::contract_class::ContractClass,
    testing::starknet_state::StarknetState as InnerStarknetState, utils::Address,
};
#[pyclass]
#[pyo3(name = "StarknetState")]
pub struct PyStarknetState {
    inner: InnerStarknetState,
}

impl PyStarknetState {
    pub fn declare(
        &mut self,
        contract_class: ContractClass,
    ) -> PyResult<([u8; 32], TransactionExecutionInfo)> {
        Ok(self
            .inner
            .declare(contract_class)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?)
    }

    pub fn invoke_raw(
        &mut self,
        contract_address: BigUint,
        selector: BigUint,
        calldata: Vec<BigUint>,
        max_fee: u64,
        signature: Option<Vec<BigUint>>,
        nonce: Option<BigUint>,
    ) -> PyResult<TransactionExecutionInfo> {
        let address = Address(contract_address.into());
        let selector = selector.into();

        let calldata = calldata
            .into_iter()
            .map(|v| Felt::from(v))
            .collect::<Vec<Felt>>();
        let signature = match signature {
            Some(signs) => Some(
                signs
                    .into_iter()
                    .map(|v| Felt::from(v))
                    .collect::<Vec<Felt>>(),
            ),
            None => None,
        };
        let nonce = match nonce {
            Some(n) => Some(Felt::from(n)),
            None => None,
        };

        Ok(self
            .inner
            .invoke_raw(address, selector, calldata, max_fee, signature, nonce)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?)
    }
}
