use cairo_rs::types::relocatable::Relocatable;
use felt::Felt252;

use crate::utils::Address;

#[allow(unused)]
pub(crate) enum SyscallRequest {
    CallContract(CallContractRequest),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CallContractRequest {
    pub(crate) selector: Felt252,
    pub(crate) contract_address: Address,
    pub(crate) function_selector: Felt252,
    pub(crate) calldata_start: Relocatable,
    pub(crate) calldata_end: Relocatable,
}
