pub fn get_syscall_size_from_name(syscall_name: &str) -> usize {
    match syscall_name {
        "emit_event" => 4,
        "deploy" => 9,
        _ => unreachable!(),
    }
}

pub fn get_deprecated_syscall_size_from_name(syscall_name: &str) -> usize {
    match syscall_name {
        "call_contract" => 7,
        "deploy" => 9,
        "emit_event" => 5,
        "get_block_number" => 2,
        "get_block_timestamp" => 2,
        "get_caller_address" => 2,
        "get_contract_address" => 2,
        "get_sequencer_address" => 2,
        "get_tx_info" => 2,
        "get_tx_signature" => 3,
        "library_call" => 7,
        "library_call_l1_handler" => 7,
        "send_message_to_l1" => 4,
        "storage_read" => 3,
        "storage_write" => 3,
        "replace_class" => 2,
        _ => unreachable!(),
    }
}
