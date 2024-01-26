use core::starknet::contract_address::ContractAddress;

#[starknet::interface]
trait IGetExecutionInfo<TContractState> {
    fn get_info(self: @TContractState) -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress);
}

#[starknet::contract]
mod GetExecutionInfo {
    use starknet::info::get_execution_info;
    use starknet::info::v2::ExecutionInfo;
    use core::starknet::contract_address::ContractAddress;
    use box::BoxTrait;
    use array::SpanTrait;

    #[storage]
    struct Storage {
    }

    #[external(v0)]
    impl GetExecutionInfo of super::IGetExecutionInfo<ContractState> {
        fn get_info(self: @ContractState) -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
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

            // V2 fields

            let resource_bounds = tx_info.resource_bounds;
            let tip = tx_info.tip;
            let paymaster_data = tx_info.paymaster_data;
            let nonce_da_mode = tx_info.nonce_data_availability_mode;
            let fee_da_mode = tx_info.fee_data_availability_mode;
            let account_deployment_data = tx_info.account_deployment_data;

            assert(block_number == 0, 'Wrong Block Number');
            assert(block_timestamp == 0, 'Wrong Block Timestamp');
            assert(version == 1, 'Wrong Version');
            assert(max_fee == 0, 'Wrong max fee');
            assert(transaction_hash == 0, 'Wrong Tx Hash');
            assert(chain_id == 1536727068981429685321, 'Wrong Chain Id');
            assert(nonce == 10, 'Wrong Nonce');
            assert(entry_point_selector == 1583979555264088613757654119588925070177786702073426169970015447448454297318, 'Wrong Entrypoint Selector');
            assert(*signature.at(0) == 22, 'Wrong Signature');
            assert(*signature.at(1) == 33, 'Wrong Signature');
            assert(signature.len() == 2, 'Wrong Signature len');
            assert(*resource_bounds.at(0).resource == 83774935613779, 'Wrong L1 gas resource name');
            assert(*resource_bounds.at(0).max_amount == 30, 'Wrong L1 gas max amount');
            assert(*resource_bounds.at(0).max_price_per_unit == 15, 'Wrong L1 gas max price per unit');
            assert(*resource_bounds.at(1).resource== 83779230581075, 'Wrong L1 gas resource name');
            assert(*resource_bounds.at(1).max_amount == 10, 'Wrong L2 gas max amount');
            assert(*resource_bounds.at(1).max_price_per_unit == 5, 'Wrong L2 gas max price per unit');
            assert(tip == 3, 'Wrong Tip');
            assert(*paymaster_data.at(0) == 6, 'Wrong Paymaster Data');
            assert(*paymaster_data.at(1) == 17, 'Wrong Paymaster Data');
            assert(paymaster_data.len() == 2, 'Wrong Paymaster Data len');
            assert(nonce_da_mode == 0, 'Wrong Nonce DA Mode');
            assert(fee_da_mode == 1, 'Wrong Fee DA Mode');
            assert(*account_deployment_data.at(0) == 7, 'Wrong Acc. Deployment Data');
            assert(*account_deployment_data.at(1) == 18, 'Wrong Acc. Deployment Data');
            assert(account_deployment_data.len() == 2, 'Wrong Acc. Deployment Data len');
            
            return (
                sequencer_address,
                account_contract_address,
                caller_address,
                contract_address
            );
        }
    }
}
