%lang starknet

@contract_interface
namespace IAMMContract {
    func get_account_token_balance(account_id: felt, token_type: felt) -> (balance: felt) {
    }

    func get_pool_token_balance(token_type: felt) -> (balance: felt) {
    }

    func swap(token_from: felt, amount_from: felt) -> (amount_to: felt) {
    }

    func add_demo_token(token_a_amount: felt, token_b_amount: felt) {
    }

    func init_pool(token_a: felt, token_b: felt) {
    }
}

@view
func proxy_get_pool_token_balance{syscall_ptr: felt*, range_check_ptr}(
    contract_address: felt, token_type: felt
) -> (balance: felt) {
    IAMMContract.init_pool(contract_address, 100, 100);
    return IAMMContract.get_pool_token_balance(contract_address, token_type);
}
