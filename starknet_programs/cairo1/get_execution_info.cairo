#[contract]
mod GetExecutionInfo {

    use starknet::info::get_execution_info;
    use starknet::info::ExecutionInfo;
    use core::starknet::contract_address::ContractAddress;
    use box::BoxTrait;
    use array::SpanTrait;

    #[external]
    fn get_info() -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
        let info = get_execution_info().unbox();
        let block_info = info.block_info.unbox();
        let tx_info = info.tx_info.unbox();

        let block_number = block_info.block_number;
        let block_timestamp = block_info.block_timestamp;
        let sequencer_address = block_info.sequencer_address;

        let version = tx_info.version;
        let account_contract_address = tx_info.account_contract_address;
        let max_fee = tx_info.max_fee;
        let signature = tx_info.signature;
        let transaction_hash = tx_info.transaction_hash;
        let chain_id = tx_info.chain_id;
        let nonce = tx_info.nonce;

        let caller_address = info.caller_address;
        let contract_address = info.contract_address;
        let entry_point_selector = info.entry_point_selector;

        assert(block_number == 0, 1);
        assert(block_timestamp == 0, 2);
        assert(version == 1, 3);
        assert(max_fee == 0, 4);
        assert(transaction_hash == 0, 5);
        assert(chain_id == 1536727068981429685321, 6);
        assert(nonce == 10, 7);
        assert(entry_point_selector == 1583979555264088613757654119588925070177786702073426169970015447448454297318, 8);
        assert(*signature.at(0) == 22, 9);
        assert(*signature.at(1) == 33, 10);
        assert(signature.len() == 2, 11);
        
        return (
            sequencer_address,
            account_contract_address,
            caller_address,
            contract_address
        );
    }
}
