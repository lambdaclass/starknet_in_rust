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

pub(crate) const CALL_CONTRACT: &str =
    "syscall_handler.call_contract(segments=segments, syscall_ptr=ids.syscall_ptr)";

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

// *************************
//     Syscall hints
// *************************

pub(crate) const ADDR_BOUND_PRIME: &str =
    "# Verify the assumptions on the relationship between 2**250, ADDR_BOUND and PRIME.\nADDR_BOUND = ids.ADDR_BOUND % PRIME\nassert (2**250 < ADDR_BOUND <= 2**251) and (2 * 2**250 < PRIME) and (\n        ADDR_BOUND * 2 > PRIME), \\\n    'normalize_address() cannot be used with the current constants.'\nids.is_small = 1 if ids.addr < ADDR_BOUND else 0";
pub(crate) const ADDR_IS_250: &str = "ids.is_250 = 1 if ids.addr < 2**250 else 0";
