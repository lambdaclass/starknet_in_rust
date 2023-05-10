use std::collections::HashMap;

use cairo_vm::{
    serde::deserialize_program::{BuiltinName, HintParams, ReferenceManager},
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
        Program::new(
            entrypoint_builtins,
            self.bytecode.clone(),
            Default::default(),
            self.pythonic_hints.clone(),
            ReferenceManager {
                references: Vec::new(),
            },
            Default::default(),
            Default::default(),
            Default::default(),
        )
        .unwrap()
    }
}
