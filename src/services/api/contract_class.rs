use cairo_rs::serde::deserialize_program::BuiltinName;

pub(crate) const SUPPORTED_BUILTINS: [BuiltinName; 5] = [
    BuiltinName::pedersen,
    BuiltinName::range_check,
    BuiltinName::ecdsa,
    BuiltinName::bitwise,
    BuiltinName::ec_op,
];

// Reexport starknet-contract-class objects
pub use starknet_contract_class::ContractClass;
pub use starknet_contract_class::ContractEntryPoint;
pub use starknet_contract_class::EntryPointType;
