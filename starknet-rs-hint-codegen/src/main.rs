use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

fn main() {
    let path = Path::new("src").join("syscalls").join("hint_code.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());

    write!(
        &mut file,
        "use super::deprecated_syscall_handler::Hint;\n\nstatic KEYWORDS: phf::Map<&'static str, Hint> = {}",
        phf_codegen::Map::new()
            .entry("syscall_handler.deploy(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::Deploy")
            .entry("syscall_handler.emit_event(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::EmitEvent")
            .entry("syscall_handler.get_sequencer_address(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::GetSequencerAddress")
            .entry("syscall_handler.storage_write(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::StorageWrite")
            .entry("syscall_handler.storage_read(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::StorageRead")
            .entry("syscall_handler.get_block_number(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::GetBlockNumber")
            .entry("syscall_handler.library_call(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::LibraryCall")
            .entry("syscall_handler.library_call_l1_handler(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::LibraryCallL1Handler")
            .entry("syscall_handler.call_contract(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::CallContract")
            .entry("syscall_handler.get_caller_address(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::GetCallerAddress")
            .entry("syscall_handler.get_block_timestamp(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::GetBlockTimestamp")
            .entry("syscall_handler.send_message_to_l1(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::SendMessageToL1")
            .entry("syscall_handler.get_tx_signature(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::GetTxSignature")
            .entry("syscall_handler.get_tx_info(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::GetTxInfo")
            .entry("syscall_handler.get_contract_address(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::GetContractAddress")
            .entry("syscall_handler.delegate_call(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::DelegateCall")
            .entry("syscall_handler.delegate_l1_handler(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::DelegateCallL1Handler")
            .entry("syscall_handler.replace_class(segments=segments, syscall_ptr=ids.syscall_ptr)", "Hint::ReplaceClass")
            .entry( "# Verify the assumptions on the relationship between 2**250, ADDR_BOUND and PRIME.\nADDR_BOUND = ids.ADDR_BOUND % PRIME\nassert (2**250 < ADDR_BOUND <= 2**251) and (2 * 2**250 < PRIME) and (\n        ADDR_BOUND * 2 > PRIME), \\\n    'normalize_address() cannot be used with the current constants.'\nids.is_small = 1 if ids.addr < ADDR_BOUND else 0", "Hint::AddrBoundPrime")
            .entry("ids.is_250 = 1 if ids.addr < 2**250 else 0", "Hint::AddrIs250")
            .build()
    )
    .unwrap();
    write!(&mut file, ";\n").unwrap();
}