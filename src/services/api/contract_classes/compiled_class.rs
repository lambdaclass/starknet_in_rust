use super::{
    casm_contract_class::CasmContractClass, deprecated_contract_class::DeprecatedContractClass,
};

pub enum CompiledClass {
    Deprecated(DeprecatedContractClass),
    Casm(CasmContractClass),
}
