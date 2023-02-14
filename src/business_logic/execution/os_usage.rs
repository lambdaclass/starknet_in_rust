use crate::definitions::transaction_type::TransactionType;
use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct OsResources {
    _execute_syscalls: HashMap<String, ExecutionResources>,
    _execute_txs_inner: HashMap<TransactionType, ExecutionResources>,
}

// TODO: add the hash maps that are in os_resources.json in cairo-lang

impl OsResources {
    pub fn new() -> Self {
        OsResources {
            ..Default::default()
        }
    }
}

pub fn get_additional_os_resources(
    _syscall_counter: HashMap<String, u64>,
    _tx_type: TransactionType,
) -> ExecutionResources {
    todo!();
}
