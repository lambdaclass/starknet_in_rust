use std::collections::HashMap;

use cairo_rs::vm::runners::cairo_runner::ExecutionResources;

use crate::definitions::transaction_type::TransactionType;

use super::error::ExecutionError;

#[derive(Debug, Clone)]
pub struct OsResources {
    _execute_syscalls: HashMap<String, ExecutionResources>,
    execute_txs_inner: HashMap<TransactionType, ExecutionResources>,
}

impl OsResources {
    pub fn default() -> Self {
        let execute_txs_inner: HashMap<TransactionType, ExecutionResources> = HashMap::from([
            (
                TransactionType::InvokeFunction,
                ExecutionResources {
                    n_steps: 2839,
                    n_memory_holes: 0,
                    builtin_instance_counter: HashMap::from([
                        ("pedersen_builtin".to_string(), 16),
                        ("range_check_builtin".to_string(), 70),
                    ]),
                },
            ),
            (
                TransactionType::Declare,
                ExecutionResources {
                    n_steps: 2336,
                    n_memory_holes: 0,
                    builtin_instance_counter: HashMap::from([
                        ("pedersen_builtin".to_string(), 15),
                        ("range_check_builtin".to_string(), 57),
                    ]),
                },
            ),
            (
                TransactionType::Deploy,
                ExecutionResources {
                    n_steps: 0,
                    n_memory_holes: 0,
                    builtin_instance_counter: HashMap::new(),
                },
            ),
            (
                TransactionType::DeployAccount,
                ExecutionResources {
                    n_steps: 3098,
                    n_memory_holes: 0,
                    builtin_instance_counter: HashMap::from([
                        ("pedersen_builtin".to_string(), 23),
                        ("range_check_builtin".to_string(), 74),
                    ]),
                },
            ),
        ]);

        OsResources {
            _execute_syscalls: HashMap::new(),
            execute_txs_inner,
        }
    }
}

pub fn get_additional_os_resources(
    _syscall_counter: HashMap<String, u64>,
    tx_type: &TransactionType,
) -> Result<ExecutionResources, ExecutionError> {
    let os_resources = OsResources::default();

    Ok(os_resources
        .execute_txs_inner
        .get(tx_type)
        .ok_or_else(|| ExecutionError::NoneTransactionType(tx_type.clone(), os_resources.clone()))?
        .clone())
}
