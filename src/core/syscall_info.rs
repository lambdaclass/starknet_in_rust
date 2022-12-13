use cairo_rs::serde::deserialize_program::*;
use cairo_rs::types::relocatable::Relocatable;
use num_bigint::BigInt;
use std::collections::HashMap;
use std::fs;

pub(crate) enum SyscallType {
    EmitEvent {
        selector: Option<Member>,
        keys_len: Option<Member>,
        keys: Option<Member>,
        data_len: Option<Member>,
        data: Option<Member>,
    },
}

pub struct SyscallInfo {
    selector: BigInt,
    syscall_size: u32,
    syscall_struct: SyscallType,
}

fn get_selector(
    selector: &str,
    identifiers: &HashMap<String, Identifier>,
) -> Result<BigInt, String> {
    identifiers
        .get(selector)
        .ok_or("Missing Members")?
        .to_owned()
        .value
        .ok_or("Missing selector value".to_string())
}

fn get_identifier(
    syscall: &str,
    identifiers: &HashMap<String, Identifier>,
) -> Result<Identifier, String> {
    Ok(identifiers
        .get(syscall)
        .ok_or("Missing identifier".to_string())?
        .to_owned())
}

impl SyscallInfo {
    pub fn emit_event(identifiers: &HashMap<String, Identifier>) -> Result<SyscallInfo, String> {
        let identifier = get_identifier("__main__.EmitEvent", identifiers)?;
        let selector = get_selector("__main__.EMIT_EVENT_SELECTOR", identifiers)?;
        let idents = identifier.members.ok_or("Missing members")?;

        let syscall_type_selector = idents.get("selector").map(ToOwned::to_owned);
        let keys_len = idents.get("keys_len").map(ToOwned::to_owned);
        let keys = idents.get("keys").map(ToOwned::to_owned);
        let data_len = idents.get("data_len").map(ToOwned::to_owned);
        let data = idents.get("data").map(ToOwned::to_owned);
        Ok(SyscallInfo {
            selector,
            syscall_size: 5,
            syscall_struct: SyscallType::EmitEvent {
                selector: syscall_type_selector,
                keys_len,
                keys,
                data_len,
                data,
            },
        })
    }
}

pub fn program_json() -> ProgramJson {
    let path = "syscalls.json";
    let file = fs::read_to_string(path).unwrap();
    serde_json::from_str(&file).unwrap()
}
