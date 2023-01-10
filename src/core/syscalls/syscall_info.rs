use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::core::errors::syscall_handler_errors::SyscallHandlerError::*;
use cairo_rs::serde::deserialize_program::*;
use felt::Felt;
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
    #[allow(unused)] // TODO: Remove once used.
    GetTxInfo {
        version: Option<Member>,
        account_contract_address: Option<Member>,
        max_fee: Option<Member>,
        signature_len: Option<Member>,
        signature: Option<Member>,
        transaction_hash: Option<Member>,
        chain_id: Option<Member>,
        nonce: Option<Member>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyscallInfo {
    selector: Felt,
    syscall_size: u64,
    syscall_struct: SyscallType,
}

#[allow(unused)] // TODO: Remove once used.
fn get_selector(
    selector: &str,
    identifiers: &HashMap<String, Identifier>,
) -> Result<Felt, SyscallHandlerError> {
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

    #[allow(unused)] // TODO: Remove once used.
    pub fn get_tx_info(
        identifiers: &HashMap<String, Identifier>,
    ) -> Result<SyscallInfo, SyscallHandlerError> {
        let identifier = get_identifier("__main__.TxInfo", identifiers)?;
        let selector = get_selector("__main__.GET_TX_INFO_SELECTOR", identifiers)?;
        let members = identifier.members.ok_or(MissingMember)?;

        let version = get_member("version", &members);
        let account_contract_address = get_member("account_contract_address", &members);
        let max_fee = get_member("max_fee", &members);
        let signature_len = get_member("signature_len", &members);
        let signature = get_member("signature", &members);
        let transaction_hash = get_member("transaction_hash", &members);
        let chain_id = get_member("chain_id", &members);
        let nonce = get_member("nonce", &members);

        Ok(SyscallInfo {
            selector,
            syscall_size: 8,
            syscall_struct: SyscallType::GetTxInfo {
                version,
                account_contract_address,
                max_fee,
                signature_len,
                signature,
                transaction_hash,
                chain_id,
                nonce,
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

    use num_traits::Num;

    use super::SyscallInfo;
    use super::*;
    use std::str::FromStr;

    #[test]
    fn create_syscall_info_emit_event() {
        let identifiers = program_json().unwrap().identifiers;
        let syscall = SyscallInfo::emit_event(&identifiers);
        assert!(syscall.is_ok());

        assert_eq!(
            SyscallInfo {
                selector: Felt::from_str_radix("1280709301550335749748", 10).unwrap(),
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

    #[test]
    fn create_syscall_get_tx_info() {
        let identifiers = program_json().unwrap().identifiers;
        let syscall = SyscallInfo::get_tx_info(&identifiers);
        assert!(syscall.is_ok());

        assert_eq!(
            SyscallInfo {
                selector: Felt::from_str_radix("1317029390204112103023", 10).unwrap(),
                syscall_size: 8,
                syscall_struct: SyscallType::GetTxInfo {
                    account_contract_address: Some(Member {
                        cairo_type: "felt".to_string(),
                        offset: 1
                    }),
                    chain_id: Some(Member {
                        cairo_type: "felt".to_string(),
                        offset: 6
                    }),
                    max_fee: Some(Member {
                        cairo_type: "felt".to_string(),
                        offset: 2
                    }),
                    nonce: Some(Member {
                        cairo_type: "felt".to_string(),
                        offset: 7
                    }),
                    signature: Some(Member {
                        cairo_type: "felt*".to_string(),
                        offset: 4
                    }),
                    signature_len: Some(Member {
                        cairo_type: "felt".to_string(),
                        offset: 3
                    }),
                    transaction_hash: Some(Member {
                        cairo_type: "felt".to_string(),
                        offset: 5
                    }),
                    version: Some(Member {
                        cairo_type: "felt".to_string(),
                        offset: 0
                    }),
                }
            },
            syscall.unwrap()
        )
    }
}
