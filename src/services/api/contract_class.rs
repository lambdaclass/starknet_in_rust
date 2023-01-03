use std::collections::HashMap;

use cairo_rs::types::program::Program;
use num_bigint::BigInt;

use crate::public::abi::AbiType;

pub(crate) const SUPPORTED_BUILTINS: [&str; 5] =
    ["pedersen", "range_check", "ecdsa", "bitwise", "ec_op"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryPointType {
    External,
    L1Handler,
    Constructor,
}

#[derive(Debug, Clone)]
pub(crate) struct ContractEntryPoint {
    pub(crate) selector: BigInt,
    pub(crate) offset: BigInt,
}

#[derive(Debug, Clone)]
pub(crate) struct ContractClass {
    pub(crate) program: Program,
    pub(crate) entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>,
    pub(crate) abi: Option<AbiType>,
}
