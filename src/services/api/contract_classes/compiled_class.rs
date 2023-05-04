use super::deprecated_contract_class::ContractClass;
use cairo_lang_starknet::casm_contract_class::CasmContractClass;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CompiledClass {
    Deprecated(Box<ContractClass>),
    Casm(Box<CasmContractClass>),
}
