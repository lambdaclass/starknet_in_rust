use std::collections::HashMap;

use cairo_rs::vm::runners::cairo_runner::ExecutionResources;

use crate::definitions::transaction_type::TransactionType;

pub fn get_additional_os_resources(
    syscall_counter: HashMap<String, u64>,
    tx_type: TransactionType,
) -> ExecutionResources {
    todo!()
}
