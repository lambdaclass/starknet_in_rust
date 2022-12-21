use num_bigint::BigInt;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct ExecutionResourcesManager(HashMap<String, u32>);

impl ExecutionResourcesManager {
    pub fn increment_syscall_counter(&mut self, syscall_name: &str, amount: u32) -> Option<()> {
        self.0.get_mut(syscall_name).map(|val| *val += amount)
    }

    pub fn get_syscall_counter(&self, syscall_name: &str) -> Option<u32> {
        self.0.get(syscall_name).map(ToOwned::to_owned)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedEvent {
    #[allow(unused)] // TODO: remove once used
    order: u32,
    #[allow(unused)] // TODO: remove once used
    keys: Vec<BigInt>,
    #[allow(unused)] // TODO: remove once used
    data: Vec<BigInt>,
}

pub(crate) struct TransactionExecutionContext {
    pub(crate) n_emitted_events: u32,
}

impl OrderedEvent {
    pub fn new(order: u32, keys: Vec<BigInt>, data: Vec<BigInt>) -> Self {
        OrderedEvent { order, keys, data }
    }
}

impl TransactionExecutionContext {
    pub fn new() -> Self {
        TransactionExecutionContext {
            n_emitted_events: 0,
        }
    }
}
