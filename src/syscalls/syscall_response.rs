use cairo_vm::felt::Felt252;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};

/// Abstracts every response variant body for each syscall.
pub(crate) enum ResponseBody {
    StorageReadResponse { value: Option<Felt252> },
    GetBlockNumber { number: Felt252 },
    Deploy(DeployResponse),
    CallContract(CallContractResponse),
    Failure(FailureReason),
    GetBlockTimestamp(GetBlockTimestampResponse),
    GetExecutionInfo { exec_info_ptr: Relocatable },
    GetBlockHash(GetBlockHashResponse),
}
/// Wraps around any response body. It also contains the remaining gas after the execution.
#[allow(unused)]
pub(crate) struct SyscallResponse {
    /// The amount of gas left after the syscall execution.
    pub gas: u128,
    /// Syscall specific response fields.
    pub body: Option<ResponseBody>,
}

impl SyscallResponse {
    /// Converts a response into cairo args for writing in memory.
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
            Some(ResponseBody::GetBlockHash(get_block_hash_response)) => {
                cairo_args.push(get_block_hash_response.block_hash.clone().into())
            }
            None => {}
        }
        cairo_args
    }
}

// ----------------------
//   Response objects
// ----------------------

/// Represents the response of get_block_timestamp syscall.
#[derive(Clone, Debug, PartialEq)]
pub struct GetBlockTimestampResponse {
    /// The block timestamp.
    pub timestamp: Felt252,
}

/// Represents the response of deploy syscall.
pub struct DeployResponse {
    /// Address of the deployed contract.
    pub contract_address: Felt252,
    /// The retdata segment start.
    pub retdata_start: Relocatable,
    /// The retdata segment end.
    pub retdata_end: Relocatable,
}

/// Represents error data of any syscall response.
pub struct FailureReason {
    /// The retdata segment start.
    pub retdata_start: Relocatable,
    /// The retdata segment end.
    pub retdata_end: Relocatable,
    // Syscall specific response fields.
    // TODO: this cause circular dependency
    //pub(crate) body: Option<ResponseBody>,
}

/// Represents the response of call_contract syscall
#[derive(Clone, Debug, PartialEq)]
pub struct CallContractResponse {
    /// The retdata segment start.
    pub retdata_start: Relocatable,
    /// The retdata segment end.
    pub retdata_end: Relocatable,
}

/// Represents the response of get_block_hash syscall
#[derive(Clone, Debug, PartialEq)]
pub struct GetBlockHashResponse {
    /// The returned hash.
    pub block_hash: Felt252,
}
