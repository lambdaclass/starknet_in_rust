// *************************
//     Syscall hints
// *************************

pub(crate) const DEPLOY: &str =
    "syscall_handler.deploy(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const EMIT_EVENT_CODE: &str =
    "syscall_handler.emit_event(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const GET_SEQUENCER_ADDRESS: &str =
    "syscall_handler.get_sequencer_address(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const STORAGE_WRITE: &str =
    "syscall_handler.storage_write(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const STORAGE_READ: &str =
    "syscall_handler.storage_read(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const SEND_MESSAGE_TO_L1: &str =
    "syscall_handler.send_message_to_l1(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const LIBRARY_CALL_L1_HANDLER: &str =
    "syscall_handler.library_call_l1_handler(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const LIBRARY_CALL: &str =
    "syscall_handler.library_call(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const GET_TX_SIGNATURE: &str =
    "syscall_handler.get_tx_signature(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const GET_TX_INFO: &str =
    "syscall_handler.get_tx_info(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const GET_CONTRACT_ADDRESS: &str =
    "syscall_handler.get_contract_address(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const GET_CALLER_ADDRESS: &str =
    "syscall_handler.get_caller_address(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const GET_BLOCK_TIMESTAMP: &str =
    "syscall_handler.get_block_timestamp(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub(crate) const GET_BLOCK_NUMBER: &str =
    "syscall_handler.get_block_number(segments=segments, syscall_ptr=ids.syscall_ptr)";
