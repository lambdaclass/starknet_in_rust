mod casm_contract_address;
mod deprecated_contract_address;
mod sierra_contract_address;

pub use casm_contract_address::compute_casm_class_hash;
pub use deprecated_contract_address::compute_deprecated_class_hash;
pub(crate) use deprecated_contract_address::compute_hinted_class_hash;
pub use sierra_contract_address::compute_sierra_class_hash;
pub use deprecated_contract_address::CairoProgramToHash;
