%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bitwise import bitwise_and, bitwise_not, bitwise_or
from starkware.cairo.common.bool import FALSE, TRUE
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin, HashBuiltin
from starkware.cairo.common.default_dict import default_dict_new, default_dict_finalize
from starkware.cairo.common.dict import dict_read, dict_write
from starkware.cairo.common.dict_access import DictAccess
from starkware.cairo.common.math import unsigned_div_rem
from starkware.cairo.common.math_cmp import is_le_felt
from starkware.starknet.common.messages import send_message_to_l1
from starkware.starknet.common.syscalls import emit_event, get_caller_address
from blockifier.rabbitx.contracts.protocol.libraries.math.safe_cmp import SafeCmp

const MESSAGE_WITHDRAW_RECEIVED = 0x1010101010101010;
const MESSAGE_DEPOSIT_RECEIVED = 1;
const WITHDRAWAL_LIMIT = 984652000000;
const NOT_FOUND_INDEX = 12345678987654321;
const WITHDRAWALS_IN_FELT = 251;

@storage_var
func admin() -> (admin_address: felt) {
}

@view
func get_admin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (admin: felt) {
    let (res) = admin.read();
    return (admin=res);
}

@storage_var
func settler() -> (settler_address: felt) {
}

@view
func get_settler{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    settler: felt
) {
    let (res) = settler.read();
    return (settler=res);
}

@storage_var
func rabbit_l1() -> (rabbit_l1_address: felt) {
}

@view
func get_rabbit_l1{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    rabbit_l1: felt
) {
    let (res) = rabbit_l1.read();
    return (rabbit_l1=res);
}

// A mapping from a trader id to their total deposited funds to date.
@storage_var
func total_deposited(trader: felt) -> (res: felt) {
}

@view
func get_total_deposited{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    trader: felt
) -> (total_deposited: felt) {
    let (res) = total_deposited.read(trader=trader);
    return (total_deposited=res);
}

// A mapping from a trader id to their total withdrawn funds to date.
@storage_var
func total_withdrawn(trader: felt) -> (res: felt) {
}

@view
func get_total_withdrawn{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    trader: felt
) -> (total_withdrawn: felt) {
    let (res) = total_withdrawn.read(trader=trader);
    return (total_withdrawn=res);
}

struct Deposit {
    trader: felt,
    amount: felt,
}

struct Withdrawal {
    id: felt,
    trader: felt,
    amount: felt,
}

@storage_var
func deactivated() -> (is_deactivated: felt) {
}

@view
func get_deactivated{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
    is_deactivated: felt
) {
    let (res) = deactivated.read();
    return (is_deactivated=res);
}

// A record of the ids of withdrawals that have been sent to L1. To save on L1 storage
// costs there are WITHDRAWALS_IN_FELT values packed into each felt. Each value is 1 or 0,
// 1 if the corresponding withdrawal has been sent, 0 if it hasn't.

@storage_var
func processed_withdrawals(withdrawal_id: felt) -> (processed: felt) {
}

@storage_var
func num_pending_deposits() -> (num_pending: felt) {
}

@view
func get_num_pending_deposits{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (num_pending: felt) {
    let (res) = num_pending_deposits.read();
    return (num_pending=res);
}

@storage_var
func first_pending_deposit() -> (first_pending: felt) {
}

@view
func get_first_pending_deposit{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ) -> (first_pending: felt) {
    let (res) = first_pending_deposit.read();
    return (first_pending=res);
}

// list of pending deposits
//
// entries are added by the deposit_handler @l1_handler
// function when a deposit notification is received
//
// entries are removed when acknowledgement of their receipt is
// made by a call to the acknowledge_deposits function
//

@storage_var
func pending_deposits(index: felt) -> (deposit_id: felt) {
}

// list of all deposits, both pending and processed
//
// entries are added by the deposit_handler @l1_handler
// function when a deposit notification is received
// entries are never removed or changed

@storage_var
func all_deposits(deposit_id: felt) -> (deposit: Deposit) {
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    admin_address: felt, settler_address: felt, rabbit_l1_address: felt
) {
    admin.write(admin_address);
    settler.write(settler_address);
    rabbit_l1.write(rabbit_l1_address);
    return ();
}

func only_admin{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    let (admin_address) = admin.read();
    let (caller_address) = get_caller_address();
    with_attr error_message("Only admin") {
        assert admin_address = caller_address;
    }
    return ();
}

func only_settler{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    let (settler_address) = settler.read();
    let (caller_address) = get_caller_address();
    with_attr error_message("Only settler") {
        assert settler_address = caller_address;
    }
    return ();
}

func only_active{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    let (contract_deactivated) = deactivated.read();
    with_attr error_message("Deactivated") {
        assert contract_deactivated = 0;
    }
    return ();
}

@external
func deactivate{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    only_admin();
    deactivated.write(1);
    return ();
}

@l1_handler
func deposit_handler{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    from_address: felt, id: felt, trader: felt, amount: felt
) {
    // Make sure the message was sent by the rabbit L1 contract.
    let (l1_contract) = rabbit_l1.read();
    assert from_address = l1_contract;
    // implementation in separate function so we can call it from a unit test since
    // @l1_handler can only be called by StarkNet when a message is received from L1
    deposit(id=id, trader=trader, amount=amount);
    return ();
}

func deposit{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    id: felt, trader: felt, amount: felt
) {
    alloc_locals;
    only_active();
    SafeCmp.assert_nn_signed(amount);
    tempvar pd: Deposit* = new Deposit(trader=trader, amount=amount);
    let (local first_p) = first_pending_deposit.read();
    let (local num_p) = num_pending_deposits.read();
    pending_deposits.write(first_p + num_p, id);
    all_deposits.write(id, [pd]);
    num_pending_deposits.write(num_p + 1);
    return ();
}

@external
func process_pending_deposits{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() {
    alloc_locals;
    only_active();
    only_settler();
    let (local first_p) = first_pending_deposit.read();
    let (local num_p) = num_pending_deposits.read();
    return do_process_pending_deposits(next_pending=first_p, stop_pending=first_p + num_p);
}

func do_process_pending_deposits{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    next_pending: felt, stop_pending: felt
) {
    alloc_locals;
    if (next_pending == stop_pending) {
        return ();
    }
    let (local id) = pending_deposits.read(next_pending);
    let (local pd) = all_deposits.read(id);
    let (keys: felt*) = alloc();
    assert keys[0] = 'deposit';
    assert keys[1] = id;
    assert keys[2] = pd.trader;
    let (data: felt*) = alloc();
    assert data[0] = pd.amount;
    emit_event(3, keys, 1, data);

    return do_process_pending_deposits(next_pending + 1, stop_pending);
}

// records where in the pending_deposits a particular deposit_id is
// and whether or not it has been seen and processed
struct DepositInfo {
    pending_index: felt,
    processed: felt,
}

@external
func acknowledge_deposits{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    ack_len: felt, ack: felt*
) {
    alloc_locals;
    only_active();
    only_settler();
    let (local first_p) = first_pending_deposit.read();
    let (local num_p) = num_pending_deposits.read();

    // index_dict is a mapping from deposit_id to a DepositInfo struct which records the index
    // of that deposit_id in the pending_deposits and whether or not the deposit has been processed.
    // We use it to efficiently find the pending deposit corresponding to each deposit_id in the
    // list of deposit ids being acknowledged, and also to track which deposit_ids we have seen.
    //
    // The dict has a default value of a struct with a pending_index of INDEX_NOT_FOUND. If this
    // default value is returned for a key of deposit_id then it is not the id of any pending deposit
    // in the dict.
    //
    // Populating the index_dict means scanning the pending
    // deposits, which is O(n) where n is the number of pending deposits. Without the dict we would
    // have to scan the pending deposits to find each acknowledged deposit_id. That would be O(n*m)
    // where m is the number of deposit ids being acknowledged. Typically m will be equal, or close,
    // to n, making that approach O(n^2).

    local deposit_not_found: DepositInfo* = new DepositInfo(
        pending_index=NOT_FOUND_INDEX, processed=0
    );
    let cast_not_found = cast(deposit_not_found, felt);
    let (local dict) = default_dict_new(default_value=cast_not_found);
    let (dict_start, dict_end) = populate_index_dict(
        num_left=num_p, pending_index=first_p, dict_start=dict, dict_end=dict
    );

    let (dict_start, dict_end) = do_acknowledge_deposits(
        num_left=ack_len,
        first=ack,
        first_pending=first_p,
        num_pending=num_p,
        dict_start=dict_start,
        dict_end=dict_end,
    );
    let (dict_start, dict_end) = pack_pending(dict_start, dict_end);
    default_dict_finalize(dict_start, dict_end, cast_not_found);
    return ();
}

// go through all the pending deposits recursively and add a dict entry for each one

func populate_index_dict{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    num_left: felt, pending_index: felt, dict_start: DictAccess*, dict_end: DictAccess*
) -> (dict_start: DictAccess*, dict_end: DictAccess*) {
    alloc_locals;
    if (num_left == 0) {
        return (dict_start, dict_end);
    }
    let (local deposit_id) = pending_deposits.read(pending_index);
    local deposit_info: DepositInfo* = new DepositInfo(pending_index=pending_index, processed=0);
    let felt_info = cast(deposit_info, felt);
    dict_write{dict_ptr=dict_end}(deposit_id, felt_info);
    return populate_index_dict(num_left - 1, pending_index + 1, dict_start, dict_end);
}

func do_acknowledge_deposits{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    num_left: felt,
    first: felt*,
    first_pending: felt,
    num_pending: felt,
    dict_start: DictAccess*,
    dict_end: DictAccess*,
) -> (dict_start: DictAccess*, dict_end: DictAccess*) {
    alloc_locals;
    if (num_left == 0) {
        return (dict_start, dict_end);
    }

    local deposit_id = [first];
    let (dict_info) = dict_read{dict_ptr=dict_end}(deposit_id);
    let deposit_info = cast(dict_info, DepositInfo*);
    local pending_index = deposit_info.pending_index;

    if (pending_index != NOT_FOUND_INDEX) {
        // record this pending_deposit as having been processed
        local updated_deposit_info: DepositInfo* = new DepositInfo(
            pending_index=pending_index, processed=1
        );
        let felt_info = cast(updated_deposit_info, felt);
        dict_write{dict_ptr=dict_end}(deposit_id, felt_info);

        // update total_deposited
        let (local d) = all_deposits.read(deposit_id);
        let (local prev_total_deposited) = total_deposited.read(d.trader);
        tempvar new_total_deposited = prev_total_deposited + d.amount;
        total_deposited.write(d.trader, new_total_deposited);

        tempvar dict_end = dict_end;
        tempvar syscall_ptr = syscall_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
        tempvar range_check_ptr = range_check_ptr;
    } else {
        tempvar dict_end = dict_end;
        tempvar syscall_ptr = syscall_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
        tempvar range_check_ptr = range_check_ptr;
    }

    return do_acknowledge_deposits(
        num_left - 1, first + 1, first_pending, num_pending, dict_start, dict_end
    );
}

func pack_pending{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    dict_start: DictAccess*, dict_end: DictAccess*
) -> (dict_start: DictAccess*, dict_end: DictAccess*) {
    alloc_locals;
    let (local first_p) = first_pending_deposit.read();
    let (local num_p) = num_pending_deposits.read();
    let (zero_slots: felt*) = alloc();
    let (non_zeros: felt*) = alloc();
    let (
        local num_zero_slots, local num_non_zeros, local dict_start, local dict_end
    ) = scan_pending(first_p, first_p + num_p, 0, zero_slots, 0, non_zeros, dict_start, dict_end);
    num_pending_deposits.write(num_non_zeros);
    if (num_non_zeros == 0) {
        first_pending_deposit.write(0);
    } else {
        let first_non_zero = non_zeros[0];
        first_pending_deposit.write(first_non_zero);
        if (num_zero_slots != 0) {
            // some but not all pending deposits have been acknowledged, rearrange
            // the pending_deposits so all the unacknowledged ones are at the start
            rewrite_pending(
                num_zero_slots=num_zero_slots,
                next_zero_slot=0,
                zero_slots=zero_slots,
                num_non_zeros=num_non_zeros,
                next_non_zero=num_non_zeros - 1,
                non_zeros=non_zeros,
            );
        }
    }
    return (dict_start, dict_end);
}

func scan_pending{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    next_pending: felt,
    stop_pending: felt,
    next_zero_slot: felt,
    zero_slots: felt*,
    next_non_zero: felt,
    non_zeros: felt*,
    dict_start: DictAccess*,
    dict_end: DictAccess*,
) -> (num_zero_slots: felt, num_non_zeros: felt, dict_start: DictAccess*, dict_end: DictAccess*) {
    alloc_locals;
    if (next_pending == stop_pending) {
        return (
            num_zero_slots=next_zero_slot,
            num_non_zeros=next_non_zero,
            dict_start=dict_start,
            dict_end=dict_end,
        );
    }
    let (deposit_id) = pending_deposits.read(next_pending);
    let (dict_entry) = dict_read{dict_ptr=dict_end}(deposit_id);
    let deposit_info = cast(dict_entry, DepositInfo*);
    let processed = deposit_info.processed;
    if (processed == 1) {
        // this pending index is marked as already seen
        assert zero_slots[next_zero_slot] = next_pending;
        return scan_pending(
            next_pending + 1,
            stop_pending,
            next_zero_slot + 1,
            zero_slots,
            next_non_zero,
            non_zeros,
            dict_start,
            dict_end,
        );
    } else {
        // this pending slot is not marked, so is still to be processed
        assert non_zeros[next_non_zero] = next_pending;
        return scan_pending(
            next_pending + 1,
            stop_pending,
            next_zero_slot,
            zero_slots,
            next_non_zero + 1,
            non_zeros,
            dict_start,
            dict_end,
        );
    }
}

func rewrite_pending{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    num_zero_slots: felt,
    next_zero_slot: felt,
    zero_slots: felt*,
    num_non_zeros: felt,
    next_non_zero: felt,
    non_zeros: felt*,
) {
    alloc_locals;
    // if we've already looked at all the zero slots then we are finsished
    if (next_zero_slot == num_zero_slots) {
        return ();
    }
    local next_zero = zero_slots[next_zero_slot];
    local first_non_zero = non_zeros[0];
    let (zero_slot_comes_after_first_non_zero) = SafeCmp.is_lt_unsigned(first_non_zero, next_zero);
    if (zero_slot_comes_after_first_non_zero == TRUE) {
        local last_non_zero = non_zeros[next_non_zero];
        let (zero_slot_comes_before_last_non_zero) = SafeCmp.is_lt_unsigned(
            next_zero, last_non_zero
        );
        if (zero_slot_comes_before_last_non_zero == TRUE) {
            let (local last_unacknowledged_deposit_id) = pending_deposits.read(last_non_zero);
            pending_deposits.write(next_zero, last_unacknowledged_deposit_id);
            let (local any_non_zeros_left) = SafeCmp.is_lt_unsigned(1, next_non_zero);
            if (any_non_zeros_left == TRUE) {
                return rewrite_pending(
                    num_zero_slots,
                    next_zero_slot + 1,
                    zero_slots,
                    num_non_zeros,
                    next_non_zero - 1,
                    non_zeros,
                );
            }
            tempvar syscall_ptr = syscall_ptr;
            tempvar pedersen_ptr = pedersen_ptr;
            tempvar range_check_ptr = range_check_ptr;
        } else {
            tempvar syscall_ptr = syscall_ptr;
            tempvar pedersen_ptr = pedersen_ptr;
            tempvar range_check_ptr = range_check_ptr;
        }
    } else {
        tempvar syscall_ptr = syscall_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
        tempvar range_check_ptr = range_check_ptr;
    }
    return ();
}

@external
func withdraw{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(withdrawals_len: felt, withdrawals: Withdrawal*) {
    alloc_locals;
    only_settler();
    only_active();

    // Use dict to hold mapping from trader to total withdrawn. The dict is populated and finalized
    // by sum_withdrawals and then used by populate_payload which iterates over it to generate one
    // trader/amount payload entry for each trader who requested any withdrawals, where the amount is
    // the sum of all the withdrawal requests for that trader.

    let (local dict) = default_dict_new(default_value=0);
    let (local total_amount, local squashed_start, local squashed_end) = sum_withdrawals(
        withdrawals_len=withdrawals_len,
        withdrawals=withdrawals,
        partial_sum=0,
        dict_start=dict,
        dict_end=dict,
    );
    if (squashed_start != squashed_end) {
        let (small_enough) = SafeCmp.is_le_signed(total_amount, WITHDRAWAL_LIMIT);
        if (small_enough == FALSE) {
            deactivate();
            return ();
        }
        do_withdraw(dict_start=squashed_start, dict_end=squashed_end);
        tempvar syscall_ptr = syscall_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
        tempvar range_check_ptr = range_check_ptr;
    } else {
        tempvar syscall_ptr = syscall_ptr;
        tempvar pedersen_ptr = pedersen_ptr;
        tempvar range_check_ptr = range_check_ptr;
    }
    return ();
}

func sum_withdrawals{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(
    withdrawals_len: felt,
    withdrawals: Withdrawal*,
    partial_sum: felt,
    dict_start: DictAccess*,
    dict_end: DictAccess*,
) -> (sum: felt, squashed_start: DictAccess*, squashed_end: DictAccess*) {
    if (withdrawals_len == 0) {
        let (squashed_start, squashed_end) = default_dict_finalize(dict_start, dict_end, 0);
        return (sum=partial_sum, squashed_start=squashed_start, squashed_end=squashed_end);
    }
    alloc_locals;
    local id = withdrawals[0].id;
    local trader = withdrawals[0].trader;
    local amount = withdrawals[0].amount;
    let (local already_sent) = get_withdrawal_sent_to_L1(withdrawals[0].id);
    // Make sure amount is positive.
    SafeCmp.assert_nn_signed(amount);
    let (keys: felt*) = alloc();
    assert keys[0] = 'withdraw';
    assert keys[1] = id;
    assert keys[2] = trader;
    let (data: felt*) = alloc();
    assert data[0] = amount;
    assert data[1] = already_sent;
    emit_event(3, keys, 2, data);
    if (already_sent == FALSE) {
        // add this withdrawal to the dictionary, first get the current value as
        // this might not be the first withdrawal for the trader in this batch
        let (old_trader_withdrawal) = dict_read{dict_ptr=dict_end}(key=trader);

        // then write the new total to the dictionary
        dict_write{dict_ptr=dict_end}(trader, old_trader_withdrawal + amount);
        // record the withdrawal so it can't be sent again
        set_withdrawal_sent_to_L1(id);

        return sum_withdrawals(
            withdrawals_len - 1,
            withdrawals + Withdrawal.SIZE,
            partial_sum + withdrawals[0].amount,
            dict_start,
            dict_end,
        );
    }
    return sum_withdrawals(
        withdrawals_len - 1, withdrawals + Withdrawal.SIZE, partial_sum, dict_start, dict_end
    );
}

func do_withdraw{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    dict_start: DictAccess*, dict_end: DictAccess*
) {
    alloc_locals;
    // Send the withdrawal message.
    let (local l1_address) = rabbit_l1.read();
    let (message_payload: felt*) = alloc();
    assert message_payload[0] = MESSAGE_WITHDRAW_RECEIVED;
    let (payload_size) = populate_payload(message_payload + 1, 1, dict_start, dict_end);
    send_message_to_l1(to_address=l1_address, payload_size=payload_size, payload=message_payload);
    return ();
}

func populate_payload{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    payload: felt*, payload_len: felt, dict_start: DictAccess*, dict_end: DictAccess*
) -> (payload_size: felt) {
    alloc_locals;
    if (dict_start == dict_end) {
        return (payload_size=payload_len);
    }
    let trader = dict_start.key;
    assert payload[0] = trader;
    let amount = dict_start.new_value;
    assert payload[1] = amount;
    // Update the new total_withdrawn
    let (prev_total_withdrawn) = total_withdrawn.read(trader=trader);
    total_withdrawn.write(trader, prev_total_withdrawn + amount);
    return populate_payload(
        payload=payload + 2,
        payload_len=payload_len + 2,
        dict_start=dict_start + DictAccess.SIZE,
        dict_end=dict_end,
    );
}

func set_withdrawal_sent_to_L1{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(withdrawal_id: felt) {
    alloc_locals;
    let (local word_index, local bit_index) = find_bit(withdrawal_id);
    let (local word_before) = processed_withdrawals.read(word_index);
    let (bit_mask) = two_to_the_n(bit_index);
    let (word_after) = bitwise_or(word_before, bit_mask);
    processed_withdrawals.write(word_index, word_after);
    return ();
}

@view
func get_withdrawal_sent_to_L1{
    syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*
}(withdrawal_id: felt) -> (value: felt) {
    alloc_locals;
    let (local word_index, local bit_index) = find_bit(withdrawal_id);
    let (local word) = processed_withdrawals.read(word_index);
    let (bit_mask) = two_to_the_n(bit_index);
    let (lsb_zeros) = bitwise_not(bit_mask - 1);
    let (rounded_down) = bitwise_and(word, lsb_zeros);
    let bit_in_lsb = rounded_down / bit_mask;
    let (bit) = bitwise_and(bit_in_lsb, 1);
    return (value=bit);
}

func find_bit{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(key: felt) -> (
    word_index: felt, bit_index: felt
) {
    let (word_index, bit_index) = unsigned_div_rem(key, WITHDRAWALS_IN_FELT);
    return (word_index, bit_index);
}

func two_to_the_n{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(n: felt) -> (
    result: felt
) {
    let result = two_to_the_n_acc(n=n, accumulator=1);
    return (result);
}

// Multiplying by 2 up to 250 times in a recursive loop is a bit inefficient, and we
// can't use the expression 2**n as Cairo v0.9 doesn't support that. We can use constant
// expressions like 2**120, so one possible approach would be to store all 250 possible
// powers of 2 and have a giant if statement that returns the correct one with no
// mutliplications required. The compromise approach used here is to store just a
// selection of the powers of 2 spread  over the range from 2 to 250 and build the
// result in a series of up to 9 (but typically 4 or 5) multiplications.

func two_to_the_n_acc{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    n: felt, accumulator: felt
) -> (result: felt) {
    if (n == 0) {
        return (result=accumulator);
    }
    let n_gt_240 = is_le_felt(240, n);
    if (n_gt_240 == 1) {
        return two_to_the_n_acc(n=n - 240, accumulator=accumulator * (2 ** 240));
    }
    let n_gt_128 = is_le_felt(128, n);
    if (n_gt_128 == 1) {
        return two_to_the_n_acc(n=n - 128, accumulator=accumulator * (2 ** 128));
    }
    let n_gt_64 = is_le_felt(64, n);
    if (n_gt_64 == 1) {
        return two_to_the_n_acc(n=n - 64, accumulator=accumulator * (2 ** 64));
    }
    let n_gt_32 = is_le_felt(32, n);
    if (n_gt_32 == 1) {
        return two_to_the_n_acc(n=n - 32, accumulator=accumulator * (2 ** 32));
    }
    let n_gt_16 = is_le_felt(16, n);
    if (n_gt_16 == 1) {
        return two_to_the_n_acc(n=n - 16, accumulator=accumulator * (2 ** 16));
    }
    let n_gt_8 = is_le_felt(8, n);
    if (n_gt_8 == 1) {
        return two_to_the_n_acc(n=n - 8, accumulator=accumulator * (2 ** 8));
    }
    let n_gt_4 = is_le_felt(4, n);
    if (n_gt_4 == 1) {
        return two_to_the_n_acc(n=n - 4, accumulator=accumulator * (2 ** 4));
    }
    let n_gt_2 = is_le_felt(2, n);
    if (n_gt_2 == 1) {
        return two_to_the_n_acc(n=n - 2, accumulator=accumulator * (2 ** 2));
    }
    return two_to_the_n_acc(n=n - 1, accumulator=accumulator * 2);
}
