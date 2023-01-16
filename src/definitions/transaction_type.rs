use crate::{business_logic::state::state_api_objects::BlockInfo, utils::Address};

#[derive(Debug, PartialEq, Default)]

// TODO: this are not the actual types, just speculation
pub struct TransactionType {
    declare: usize,
    deploy: usize,
    deploy_account: Address,
    initialize_block_info: BlockInfo,
    l1_handler: String,
    invoke_function: String,
}
