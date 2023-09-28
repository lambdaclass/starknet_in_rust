use super::{deprecated_syscall_handler::Hint, hint_code};

pub(crate) static HINTCODE: phf::Map<&'static str, Hint> = ::phf::Map {
    key: 7485420634051515786,
    disps: &[
        (1, 19),
        (2, 0),
        (0, 8),
        (7, 4),
    ],
    entries: &[
        (hint_code::GET_BLOCK_TIMESTAMP, Hint::GetBlockTimestamp),
        (hint_code::GET_BLOCK_NUMBER, Hint::GetBlockNumber),
        (hint_code::GET_TX_SIGNATURE, Hint::GetTxSignature),
        (hint_code::STORAGE_WRITE, Hint::StorageWrite),
        (hint_code::CALL_CONTRACT, Hint::CallContract),
        (hint_code::LIBRARY_CALL, Hint::LibraryCall),
        (hint_code::STORAGE_READ, Hint::StorageRead),
        (hint_code::SEND_MESSAGE_TO_L1, Hint::SendMessageToL1),
        (hint_code::REPLACE_CLASS, Hint::ReplaceClass),
        (hint_code::GET_TX_INFO, Hint::GetTxInfo),
        (hint_code::GET_CONTRACT_ADDRESS, Hint::GetContractAddress),
        (hint_code::GET_SEQUENCER_ADDRESS, Hint::GetSequencerAddress),
        (hint_code::ADDR_BOUND_PRIME, Hint::AddrBoundPrime),
        (hint_code::LIBRARY_CALL_L1_HANDLER, Hint::LibraryCallL1Handler),
        (hint_code::DELEGATE_CALL, Hint::DelegateCall),
        (hint_code::DELEGATE_L1_HANDLER, Hint::DelegateCallL1Handler),
        (hint_code::EMIT_EVENT_CODE, Hint::EmitEvent),
        (hint_code::DEPLOY, Hint::Deploy),
        (hint_code::GET_CALLER_ADDRESS, Hint::GetCallerAddress),
        (hint_code::ADDR_IS_250, Hint::AddrIs250),
    ],
};
