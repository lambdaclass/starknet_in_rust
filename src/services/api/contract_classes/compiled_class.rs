use super::{casm_contract_class::CasmContractClass, deprecated_contract_class::ContractClass};

pub enum CompiledClass {
    Deprecated(Box<ContractClass>),
    Casm(Box<CasmContractClass>),
}
