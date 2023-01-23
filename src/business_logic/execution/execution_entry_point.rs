use felt::Felt;

use crate::{services::api::contract_class::EntryPointType, utils::Address};

use super::objects::CallType;

/// Represents a Cairo entry point execution of a StarkNet contract.
#[derive(Debug)]
pub struct ExecutionEntryPoint {
    call_type: CallType,
    contract_address: Address,
    code_address: Option<Address>,
    class_hash: Option<[u8; 32]>,
    calldata: Vec<Felt>,
    caller_address: Address,
    entry_point_selector: usize,
    entry_point_type: EntryPointType,
}

impl ExecutionEntryPoint {
    pub fn create(
        contract_address: Address,
        calldata: Vec<Felt>,
        entry_point_selector: usize,
        caller_address: Address,
        entry_point_type: EntryPointType,
        call_type: Option<CallType>,
        class_hash: Option<[u8; 32]>,
    ) -> Self {
        ExecutionEntryPoint {
            call_type: call_type.unwrap_or(CallType::Call),
            contract_address,
            code_address: None,
            class_hash,
            calldata,
            caller_address,
            entry_point_selector,
            entry_point_type,
        }
    }
}
