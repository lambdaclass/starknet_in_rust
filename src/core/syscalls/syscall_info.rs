use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::core::errors::syscall_handler_errors::SyscallHandlerError::*;
use cairo_rs::serde::deserialize_program::*;
use num_bigint::BigInt;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SyscallType {
    #[allow(unused)] // TODO: Remove once used.
    EmitEvent {
        selector: Option<Member>,
        keys_len: Option<Member>,
        keys: Option<Member>,
        data_len: Option<Member>,
        data: Option<Member>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyscallInfo {
    selector: BigInt,
    syscall_size: u32,
    syscall_struct: SyscallType,
}

#[allow(unused)] // TODO: Remove once used.
fn get_selector(
    selector: &str,
    identifiers: &HashMap<String, Identifier>,
) -> Result<BigInt, SyscallHandlerError> {
    identifiers
        .get(selector)
        .ok_or(MissingMember)?
        .clone()
        .value
        .ok_or(MissingSelector)
}

#[allow(unused)] // TODO: Remove once used.
fn get_identifier(
    syscall: &str,
    identifiers: &HashMap<String, Identifier>,
) -> Result<Identifier, SyscallHandlerError> {
    Ok(identifiers.get(syscall).ok_or(MissingIdentifiers)?.clone())
}

#[allow(unused)] // TODO: Remove once used.
fn get_member(key: &str, members: &HashMap<String, Member>) -> Option<Member> {
    members.get(key).map(ToOwned::to_owned)
}

impl SyscallInfo {
    #[allow(unused)] // TODO: Remove once used.
    pub fn emit_event(
        identifiers: &HashMap<String, Identifier>,
    ) -> Result<SyscallInfo, SyscallHandlerError> {
        let identifier = get_identifier("__main__.EmitEvent", identifiers)?;
        let selector = get_selector("__main__.EMIT_EVENT_SELECTOR", identifiers)?;
        let members = identifier.members.ok_or(MissingMember)?;

        let syscall_type_selector = get_member("selector", &members);
        let keys_len = get_member("keys_len", &members);
        let keys = get_member("keys", &members);
        let data_len = get_member("data_len", &members);
        let data = get_member("data", &members);

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

pub fn program_json() -> Result<ProgramJson, SyscallHandlerError> {
    let path = Path::new(file!())
        .parent()
        .ok_or(MissingSyscallsJsonFile)?
        .join("../../../cairo_syscalls/syscalls.json");

    let file = fs::read_to_string(path).unwrap();
    serde_json::from_str(&file).map_err(|_| MissingSyscallsJsonFile)
}

#[cfg(test)]
mod tests {

    use super::SyscallInfo;
    use super::*;
    use crate::utils::test_utils::*;
    use num_bigint::BigInt;
    use std::str::FromStr;

    #[test]
    fn create_syscall_info_emit_event() {
        let identifiers = program_json().unwrap().identifiers;
        let syscall = SyscallInfo::emit_event(&identifiers);
        assert!(syscall.is_ok());

        assert_eq!(
            SyscallInfo {
                selector: BigInt::from_str("1280709301550335749748").unwrap(),
                syscall_size: 5,
                syscall_struct: SyscallType::EmitEvent {
                    selector: Some(Member {
                        cairo_type: "felt".to_string(),
                        offset: 0,
                    }),
                    keys: Some(Member {
                        cairo_type: "felt*".to_string(),
                        offset: 2,
                    }),
                    keys_len: Some(Member {
                        cairo_type: "felt".to_string(),
                        offset: 1,
                    }),
                    data: Some(Member {
                        cairo_type: "felt*".to_string(),
                        offset: 4,
                    }),
                    data_len: Some(Member {
                        cairo_type: "felt".to_string(),
                        offset: 3,
                    })
                }
            },
            syscall.unwrap()
        )
    }
}
