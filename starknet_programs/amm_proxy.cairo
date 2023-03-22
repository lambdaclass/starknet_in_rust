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
func proxy_get_account_token_balance{syscall_ptr: felt*, range_check_ptr}(
    contract_address: felt, account_id: felt, token_type: felt
) -> (balance: felt) {
    return IAMMContract.get_account_token_balance(contract_address, account_id, token_type);
}

@view
func proxy_get_pool_token_balance{syscall_ptr: felt*, range_check_ptr}(
    contract_address: felt, token_type: felt
) -> (balance: felt) {
    return IAMMContract.get_pool_token_balance(contract_address, token_type);
}


@external
func proxy_swap{syscall_ptr: felt*, range_check_ptr}(
    contract_address: felt, token_from: felt, amount_from: felt
) -> (amount_to: felt) {
    return IAMMContract.swap(contract_address, token_from, amount_from);
}

@external
func proxy_add_demo_token{syscall_ptr: felt*, range_check_ptr}(
    contract_address: felt, token_a_amount: felt, token_b_amount: felt
) {
    return IAMMContract.add_demo_token(contract_address, token_a_amount, token_b_amount);
}

@external
func proxy_init_pool{syscall_ptr: felt*, range_check_ptr}(
    contract_address: felt, token_a: felt, token_b: felt
) {
    return IAMMContract.init_pool(contract_address, token_a, token_b);
}
