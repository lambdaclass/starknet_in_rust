from starkware.cairo.common.uint256 import Uint256

namespace DataTypes {
    struct ReserveConfiguration {
        ltv: felt,
        liquidation_threshold: felt,
        liquidation_bonus: felt,
        decimals: felt,
        reserve_active: felt,
        reserve_frozen: felt,
        borrowing_enabled: felt,
        stable_rate_borrowing_enabled: felt,
        asset_paused: felt,
        borrowable_in_isolation: felt,
        siloed_borrowing: felt,
        reserve_factor: felt,
        borrow_cap: felt,
        supply_cap: felt,
        liquidation_protocol_fee: felt,
        eMode_category: felt,
        unbacked_mint_cap: felt,
        debt_ceiling: felt,
    }

    struct ReserveData {
        configuration: ReserveConfiguration,
        liquidity_index: felt,
        current_liquidity_rate: felt,
        variable_borrow_index: felt,
        current_variable_borrow_rate: felt,
        current_stable_borrow_rate: felt,
        last_update_timestamp: felt,
        id: felt,
        a_token_address: felt,
        stable_debt_token_address: felt,
        variable_debt_token_address: felt,
        interest_rate_strategy_address: felt,
        accrued_to_treasury: felt,
        unbacked: felt,
        isolation_mode_total_debt: felt,
    }

    struct ReserveCache {
        curr_scaled_variable_debt: felt,
        next_scaled_variable_debt: felt,
        curr_principal_stable_debt: felt,
        curr_avg_stable_borrow_rate: felt,
        curr_total_stable_debt: felt,
        next_avg_stable_borrow_rate: felt,
        next_total_stable_debt: felt,
        curr_liquidity_index: felt,
        next_liquidity_index: felt,
        curr_variable_borrow_index: felt,
        next_variable_borrow_index: felt,
        curr_liquidity_rate: felt,
        curr_variable_borrow_rate: felt,
        reserve_factor: felt,
        a_token_address: felt,
        stable_debt_token_address: felt,
        variable_debt_token_address: felt,
        reserve_last_update_timestamp: felt,
        stable_debt_last_update_timestamp: felt,
        configuration: ReserveConfiguration,
    }

    struct InitReserveParams {
        asset: felt,
        a_token_address: felt,
        stable_debt_token_address: felt,
        variable_debt_token_address: felt,
        interest_rate_strategy_address: felt,
        reserves_count: felt,
        max_number_reserves: felt,
    }

    struct UserConfigurationMap {
        borrowing: felt,
        using_as_collateral: felt,
    }

    struct ExecuteSupplyParams {
        asset: felt,
        amount: Uint256,
        on_behalf_of: felt,
        referral_code: felt,
    }

    struct ExecuteWithdrawParams {
        asset: felt,
        amount: Uint256,
        to: felt,
        reserves_count: felt,
        // TODO add the rest of the fields
        // member oracle  : felt
        // member user_eMode_category  : felt
    }

    // @dev UserState - additionalData is a flexible field.
    // ATokens and VariableDebtTokens use this field store the index of the user's last supply/withdrawal/borrow/repayment.
    // StableDebtTokens use this field to store the user's stable rate.
    struct UserState {
        balance: felt,
        additional_data: felt,
    }
}
