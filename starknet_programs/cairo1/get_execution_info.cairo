#[contract]
mod GetExecutionInfo {

    use starknet::info::get_execution_info;
    use starknet::info::get_caller_address;
    use starknet::info::ExecutionInfo;
    use box::BoxTrait;

    #[external]
    fn get_info() -> felt252 {
        let info = get_execution_info().unbox();
        let block_info = info.block_info.unbox();
        let tx_info = info.tx_info.unbox();

        let block_number = block_info.block_number;
        let block_timestamp = block_info.block_timestamp;
        let sequencer_address = block_info.sequencer_address;

        let version = tx_info.version;
        let account_contract_address = tx_info.account_contract_address;
        let max_fee = tx_info.max_fee;
        let transaction_hash = tx_info.transaction_hash;
        let chain_id = tx_info.chain_id;
        let nonce = tx_info.nonce;

        let caller_address = info.caller_address;
        let contract_address = info.contract_address;
        let entry_point_selector = info.entry_point_selector;

        return version;
    }
}
