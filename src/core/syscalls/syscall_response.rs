use cairo_vm::felt::Felt252;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};

// TODO: remove once used.
#[allow(dead_code)]
pub(crate) enum ResponseBody {
    StorageReadResponse { value: Option<Felt252> },
    GetBlockNumber { number: Felt252 },
    Deploy(DeployResponse),
    CallContract(CallContractResponse),
    Failure(FailureReason),
    GetBlockTimestamp(GetBlockTimestampResponse),
    GetExecutionInfo { exec_info_ptr: Relocatable },
}
#[allow(unused)]
pub(crate) struct SyscallResponse {
    /// The amount of gas left after the syscall execution.
    pub gas: u128,
    /// Syscall specific response fields.
    pub body: Option<ResponseBody>,
}

impl SyscallResponse {
    pub(crate) fn to_cairo_compatible_args(&self) -> Vec<MaybeRelocatable> {
        let mut cairo_args = Vec::<MaybeRelocatable>::with_capacity(5);
        cairo_args.push(Felt252::from(self.gas).into());
        cairo_args
            .push(Felt252::from(matches!(self.body, Some(ResponseBody::Failure(_))) as u8).into());
        match self.body.as_ref() {
            Some(ResponseBody::StorageReadResponse { value }) => {
                if let Some(v) = value.as_ref() {
                    cairo_args.push(v.clone().into())
                }
            }
            Some(ResponseBody::GetBlockNumber { number }) => cairo_args.push(number.into()),
            Some(ResponseBody::Deploy(deploy_response)) => {
                cairo_args.push(deploy_response.contract_address.clone().into());
                cairo_args.push(deploy_response.retdata_start.into());
                cairo_args.push(deploy_response.retdata_end.into());
            }
            Some(ResponseBody::CallContract(call_contract_response)) => {
                cairo_args.push(call_contract_response.retdata_start.into());
                cairo_args.push(call_contract_response.retdata_end.into());
            }
            Some(ResponseBody::Failure(failure_reason)) => {
                cairo_args.push(failure_reason.retdata_start.into());
                cairo_args.push(failure_reason.retdata_end.into());
            }
            Some(ResponseBody::GetBlockTimestamp(get_block_timestamp_response)) => {
                cairo_args.push(get_block_timestamp_response.timestamp.clone().into())
            }
            Some(ResponseBody::GetExecutionInfo { exec_info_ptr }) => {
                cairo_args.push(exec_info_ptr.into())
            }
            None => {}
        }
        cairo_args
    }
}

// ----------------------
//   Response objects
// ----------------------

#[derive(Clone, Debug, PartialEq)]
pub struct GetBlockTimestampResponse {
    pub timestamp: Felt252,
}

pub struct DeployResponse {
    pub contract_address: Felt252,
    pub retdata_start: Relocatable,
    pub retdata_end: Relocatable,
}

pub struct FailureReason {
    pub retdata_start: Relocatable,
    pub retdata_end: Relocatable,
    // Syscall specific response fields.
    // TODO: this cause circular dependency
    //pub(crate) body: Option<ResponseBody>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CallContractResponse {
    pub retdata_start: Relocatable,
    pub retdata_end: Relocatable,
}
