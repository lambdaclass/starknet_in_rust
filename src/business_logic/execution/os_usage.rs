use std::collections::HashMap;

use cairo_rs::vm::runners::cairo_runner::ExecutionResources;

use crate::definitions::transaction_type::TransactionType;

#[derive(Debug, Clone, Default)]
pub struct OsResources {
    execute_syscalls: HashMap<String, ExecutionResources>,
    execute_txs_inner: HashMap<TransactionType, ExecutionResources>,
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
    syscall_counter: HashMap<String, u64>,
    tx_type: TransactionType,
) -> ExecutionResources {
    todo!();
}
