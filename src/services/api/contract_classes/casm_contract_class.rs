use std::collections::HashMap;

use cairo_rs::{
    serde::deserialize_program::{BuiltinName, HintParams},
    types::{program::Program, relocatable::MaybeRelocatable},
};

use super::deprecated_contract_class::{ContractEntryPoint, EntryPointType};

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct CasmContractClass {
    pub prime: String,
    pub compiler_version: String,
    pub bytecode: Vec<MaybeRelocatable>,
    pub hints: HashMap<usize, Vec<HintParams>>,

    // Optional pythonic hints in a format that can be executed by the python vm.
    pub pythonic_hints: HashMap<usize, Vec<HintParams>>,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<ContractEntryPoint>>,
}

impl CasmContractClass {
    #[allow(dead_code)]
    fn get_runnable_program(&self, entrypoint_builtins: Vec<BuiltinName>) -> Program {
        Program {
            builtins: entrypoint_builtins,
            prime: self.prime.clone(),
            data: self.bytecode.clone(),
            hints: self.pythonic_hints.clone(),
            ..Default::default()
        }
    }
}
