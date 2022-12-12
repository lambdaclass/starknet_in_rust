use cairo_rs::serde::deserialize_program::*;
use cairo_rs::types::relocatable::Relocatable;
use num_bigint::BigInt;
use std::fs;

pub(crate) enum SyscallType {
    EmitEvent {
        selector: BigInt,
        keys_len: BigInt,
        keys: Relocatable,
        data_len: BigInt,
        data: Relocatable,
    },
}

pub struct SyscallInfo {
    selector: Option<BigInt>,
    syscall_size: u32,
    syscall_struct: SyscallType,
}

impl SyscallInfo {
    pub fn emit_event(identifier: Identifier) -> SyscallInfo {
        let syscall_info_selector = identifier.members.unwrap();
        let selector: BigInt;
        let keys_len: BigInt;
        let keys: Relocatable;
        let data_len: BigInt;
        let data: Relocatable;
        SyscallInfo {
            selector: syscall_info_selector,
            syscall_size: 5,
            syscall_struct: SyscallType::EmitEvent {
                selector,
                keys_len,
                keys,
                data_len,
                data,
            },
        }
    }
}

pub fn program_json() -> ProgramJson {
    let path = "syscalls.json";
    let file = fs::read_to_string(path).unwrap();
    serde_json::from_str(&file).unwrap()
}
