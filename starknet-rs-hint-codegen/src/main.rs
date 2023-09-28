use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use starknet_in_rust::syscalls::hint_code;
use starknet_in_rust::syscalls::hint_code::*;


fn main() {
    let path = Path::new("src").join("syscalls").join("hint_code_map.rs");
    let mut file = BufWriter::new(File::create(path).unwrap());

    write!(
        &mut file,
        "use super::deprecated_syscall_handler::Hint;\n\npub(crate) static HINTCODE: phf::Map<&'static str, Hint> = {}",
        phf_codegen::Map::new()
            .entry(hint_code::DEPLOY, "Hint::Deploy")
            .entry(hint_code::EMIT_EVENT_CODE, "Hint::EmitEvent")
            .entry(hint_code::GET_SEQUENCER_ADDRESS, "Hint::GetSequencerAddress")
            .entry(hint_code::STORAGE_WRITE, "Hint::StorageWrite")
            .entry(hint_code::STORAGE_READ, "Hint::StorageRead")
            .entry(hint_code::GET_BLOCK_NUMBER, "Hint::GetBlockNumber")
            .entry(hint_code::LIBRARY_CALL, "Hint::LibraryCall")
            .entry(hint_code::LIBRARY_CALL_L1_HANDLER, "Hint::LibraryCallL1Handler")
            .entry(hint_code::CALL_CONTRACT, "Hint::CallContract")
            .entry(hint_code::GET_CALLER_ADDRESS, "Hint::GetCallerAddress")
            .entry(hint_code::GET_BLOCK_TIMESTAMP, "Hint::GetBlockTimestamp")
            .entry(hint_code::SEND_MESSAGE_TO_L1, "Hint::SendMessageToL1")
            .entry(hint_code::GET_TX_SIGNATURE, "Hint::GetTxSignature")
            .entry(hint_code::GET_TX_INFO, "Hint::GetTxInfo")
            .entry(hint_code::GET_CONTRACT_ADDRESS, "Hint::GetContractAddress")
            .entry(hint_code::DELEGATE_CALL, "Hint::DelegateCall")
            .entry(hint_code::DELEGATE_L1_HANDLER, "Hint::DelegateCallL1Handler")
            .entry(hint_code::REPLACE_CLASS, "Hint::ReplaceClass")
            .entry(hint_code::ADDR_BOUND_PRIME, "Hint::AddrBoundPrime")
            .entry(hint_code::ADDR_IS_250, "Hint::AddrIs250")
            .build()
    )
    .unwrap();
    writeln!(&mut file, ";").unwrap();
}
