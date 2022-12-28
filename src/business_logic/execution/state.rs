use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct ExecutionResourcesManager(HashMap<String, u64>);

impl ExecutionResourcesManager {
    pub fn increment_syscall_counter(&mut self, syscall_name: &str, amount: u64) -> Option<()> {
        self.0.get_mut(syscall_name).map(|val| *val += amount)
    }

    pub fn get_syscall_counter(&self, syscall_name: &str) -> Option<u64> {
        self.0.get(syscall_name).map(ToOwned::to_owned)
    }
}
