use super::deprecated_syscall_handler::Hint;

pub(crate) static HINTCODE: phf::Map<&'static str, Hint> = ::phf::Map {
    key: 12913932095322966823,
    disps: &[
        (1, 0),
        (3, 14),
        (8, 4),
        (7, 18),
    ],
    entries: &[
        ("syscall_handler.replace_class(segments=segments, syscall_ptr=ids.syscall_ptr)", super::deprecated_syscall_handler::Hint::ReplaceClass),
        ("syscall_handler.get_block_timestamp(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::GetBlockTimestamp),
        ("syscall_handler.get_caller_address(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::GetCallerAddress),
        ("syscall_handler.library_call(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::LibraryCall),
        ("syscall_handler.call_contract(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::CallContract),
        ("syscall_handler.delegate_call(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::DelegateCall),
        ("syscall_handler.get_sequencer_address(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::GetSequencerAddress),
        ("syscall_handler.get_tx_signature(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::GetTxSignature),
        ("syscall_handler.get_block_number(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::GetBlockNumber),
        ("syscall_handler.storage_write(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::StorageWrite),
        ("syscall_handler.emit_event(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::EmitEvent),
        ("syscall_handler.storage_read(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::StorageRead),
        ("ids.is_250 = 1 if ids.addr < 2**250 else 0", Hint::AddrIs250),
        ("syscall_handler.delegate_l1_handler(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::DelegateCallL1Handler),
        ("syscall_handler.deploy(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::Deploy),
        ("syscall_handler.send_message_to_l1(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::SendMessageToL1),
        ("syscall_handler.get_contract_address(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::GetContractAddress),
        ("syscall_handler.library_call_l1_handler(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::LibraryCallL1Handler),
        ("syscall_handler.get_tx_info(segments=segments, syscall_ptr=ids.syscall_ptr)", Hint::GetTxInfo),
        ("# Verify the assumptions on the relationship between 2**250, ADDR_BOUND and PRIME.\nADDR_BOUND = ids.ADDR_BOUND % PRIME\nassert (2**250 < ADDR_BOUND <= 2**251) and (2 * 2**250 < PRIME) and (\n        ADDR_BOUND * 2 > PRIME), \\\n    'normalize_address() cannot be used with the current constants.'\nids.is_small = 1 if ids.addr < ADDR_BOUND else 0", Hint::AddrBoundPrime),
    ],
};
