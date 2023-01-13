use super::objects::L2toL1MessageInfo;
use crate::definitions::constants::*;
use crate::services::eth_definitions::eth_gas_constans::*;

/// Returns an estimation of the L1 gas amount that will be used (by StarkNet's update state and
/// the verifier) following the addition of a transaction with the given parameters to a batch;
/// e.g., a message from L2 to L1 is followed by a storage write operation in StarkNet L1 contract
/// which requires gas.
/// Arguments:
/// l1_handler_payload_size should be an int if and only if we calculate the gas usage of an
/// InternalInvokeFunction of type L1 handler. Otherwise the payload size is irrelevant, and should
/// be None.
/// n_deployments is the number of the contracts deployed by the transaction.

pub fn calculate_tx_gas_usage(
    l2_to_l1_messages: Vec<L2toL1MessageInfo>,
    n_modified_contracts: usize,
    n_storage_changes: usize,
    l1_handler_payload_size: Option<usize>,
    n_deployments: usize,
) -> usize {
    let residual_message_segment_length =
        get_message_segment_lenght(&l2_to_l1_messages, l1_handler_payload_size);

    let residual_onchain_data_segment_length =
        get_onchain_data_segment_length(n_modified_contracts, n_storage_changes, n_deployments);

    let n_l2_to_l1_messages = l2_to_l1_messages.len();
    let n_l1_to_l2_messages = match l1_handler_payload_size {
        Some(_size) => 1,
        None => 0,
    };

    let starknet_gas_usage = starknet_gas_usage(
        residual_message_segment_length,
        n_l2_to_l1_messages,
        n_l1_to_l2_messages,
        l1_handler_payload_size,
        &l2_to_l1_messages,
    );

    let sharp_gas_usage = (residual_message_segment_length * SHARP_GAS_PER_MEMORY_WORD)
        + (residual_onchain_data_segment_length * SHARP_GAS_PER_MEMORY_WORD);

    starknet_gas_usage + sharp_gas_usage
}

// ~~~~~~~~~~~~~~~~
// Helper function
// ~~~~~~~~~~~~~~~~

fn starknet_gas_usage(
    residual_msg_lenght: usize,
    l2_to_l1_msg_len: usize,
    l1_to_l2_msg_len: usize,
    l1_handler: Option<usize>,
    l2_to_l1_messages: &[L2toL1MessageInfo],
) -> usize {
    let l2_emissions_cost = get_consumed_message_to_l2_emissions_cost(l1_handler);
    let l1_log_emissions_cost = get_log_message_to_l1_emissions_cost(l2_to_l1_messages);

    (residual_msg_lenght * GAS_PER_MEMORY_WORD)
        + (l2_to_l1_msg_len * GAS_PER_ZERO_TO_NONZERO_STORAGE_SET)
        + (l1_to_l2_msg_len * GAS_PER_COUNTER_DECREASE)
        + l2_emissions_cost
        + l1_log_emissions_cost
}

/// Returns the number of felts added to the output messages segment as a result of adding
/// a transaction with the given parameters to a batch. Note that constant cells - such as the one
/// that holds the segment size - are not counted.

pub fn get_message_segment_lenght(
    l2_to_l1_messages: &[L2toL1MessageInfo],
    l1_handler_payload_size: Option<usize>,
) -> usize {
    let message_segment_length = l2_to_l1_messages.iter().fold(0, |acc, msg| {
        acc + L2_TO_L1_MSG_HEADER_SIZE + msg.payload.len()
    });

    match l1_handler_payload_size {
        Some(size) => message_segment_length + L1_TO_L2_MSG_HEADER_SIZE + size,
        None => message_segment_length,
    }
}

/// Returns the number of felts added to the output data availability segment as a result of adding
/// a transaction to a batch. Note that constant cells - such as the one that holds the number of
/// modified contracts - are not counted.
/// This segment consists of deployment info (of contracts deployed by the transaction) and
/// storage updates.

pub fn get_onchain_data_segment_length(
    n_modified_contracts: usize,
    n_storage_changes: usize,
    n_deployments: usize,
) -> usize {
    n_modified_contracts * 2 + n_storage_changes * 2 + n_deployments * DEPLOYMENT_INFO_SIZE
}

/// Returns the cost of ConsumedMessageToL2 event emissions caused by an L1 handler with the given
/// payload size.
pub fn get_consumed_message_to_l2_emissions_cost(l1_handler: Option<usize>) -> usize {
    match l1_handler {
        None => 0,
        Some(size) => get_event_emission_cost(
            CONSUMED_MSG_TO_L2_N_TOPICS,
            size + CONSUMED_MSG_TO_L2_ENCODED_DATA_SIZE,
        ),
    }
}

/// Returns the cost of LogMessageToL1 event emissions caused by the given messages.
pub fn get_log_message_to_l1_emissions_cost(l2_to_l1_messages: &[L2toL1MessageInfo]) -> usize {
    l2_to_l1_messages.iter().fold(0, |acc, msg| {
        acc + get_event_emission_cost(
            LOG_MSG_TO_L1_N_TOPICS,
            LOG_MSG_TO_L1_ENCODED_DATA_SIZE + msg.payload.len(),
        )
    })
}

pub fn get_event_emission_cost(topics: usize, l1_handler_payload_size: usize) -> usize {
    GAS_PER_LOG
        + (topics + N_DEFAULT_TOPICS) * GAS_PER_LOG_TOPIC
        + l1_handler_payload_size * GAS_PER_LOG_DATA_WORD
}

#[cfg(test)]
mod tests {
    use super::get_event_emission_cost;
    use super::*;
    use crate::{
        address,
        business_logic::execution::objects::{
            L2toL1MessageInfo, OrderedEvent, OrderedL2ToL1Message,
        },
    };
    use num_bigint::BigInt;

    #[test]
    fn test_event_emission_cost() {
        let topics = 40;
        let l1_handler_payload_size = 9;
        // GAS_PER_LOG = 375
        // N_DEFAULT_TOPICS = 1
        // GAS_PER_LOG_TOPIC = 375
        // GAS_PER_LOG_DATA_WORD = 8 * 32
        assert_eq!(
            18054,
            get_event_emission_cost(topics, l1_handler_payload_size)
        );
    }

    #[test]
    fn log_messages_cost_test() {
        let ord_ev1 = OrderedL2ToL1Message::new(1, address!("1235"), vec![4.into()]);
        let ord_ev2 = OrderedL2ToL1Message::new(2, address!("35"), vec![5.into(), 6.into()]);
        let message1 = L2toL1MessageInfo::new(ord_ev1, address!("1234"));
        let message2 = L2toL1MessageInfo::new(ord_ev2, address!("1235"));

        // LOG_MSG_TO_L1_N_TOPICS = 2
        // LOG_MSG_TO_L1_ENCODED_DATA_SIZE = 2
        assert_eq!(
            get_log_message_to_l1_emissions_cost(&[message1, message2]),
            4792
        )
    }

    #[test]
    fn l2_emission_cost() {
        let l1_handler_1 = Some(10);
        let l1_handler_2 = None;

        // CONSUMED_MSG_TO_L2_N_TOPICS = 3
        // CONSUMED_MSG_TO_L2_ENCODED_DATA_SIZE = 3
        // result = emission_cost(3, 3+10)
        assert_eq!(
            get_consumed_message_to_l2_emissions_cost(l1_handler_1),
            5203
        );
        assert_eq!(get_consumed_message_to_l2_emissions_cost(l1_handler_2), 0);
    }

    #[test]
    fn message_segment_len() {
        let ord_ev1 = OrderedL2ToL1Message::new(1, address!("1235"), vec![4.into()]);
        let ord_ev2 = OrderedL2ToL1Message::new(2, address!("35"), vec![5.into(), 6.into()]);
        let message1 = L2toL1MessageInfo::new(ord_ev1, address!("1234"));
        let message2 = L2toL1MessageInfo::new(ord_ev2, address!("1235"));

        let ord_ev3 = OrderedL2ToL1Message::new(1, address!("1235"), vec![5.into(), 6.into()]);
        let ord_ev4 = OrderedL2ToL1Message::new(2, address!("35"), vec![4.into()]);
        let message3 = L2toL1MessageInfo::new(ord_ev3, address!("1234"));
        let message4 = L2toL1MessageInfo::new(ord_ev4, address!("1235"));

        let l1_handler_1 = Some(10);
        let l1_handler_2 = None;

        // L2_TO_L1_MSG_HEADER_SIZE = 3
        // iterations
        // initial value: acc = 0
        // first iteration: acc + 3 + 1 -> acc = 4
        // second iteration: acc + 3 + 2 = 9
        // 9 + 5 + size
        assert_eq!(
            get_message_segment_lenght(&[message1, message2], l1_handler_1),
            24
        );

        // iterations
        // initial value: acc = 0
        // first iteration: acc + 3 + 2 -> acc = 5
        // second iteration: acc + 3 + 1 = 9
        // 9
        assert_eq!(
            get_message_segment_lenght(&[message3, message4], l1_handler_2),
            9
        );
    }

    #[test]
    fn transaction_gas_usage_test() {
        let ord_ev1 = OrderedL2ToL1Message::new(1, address!("1235"), vec![4.into()]);
        let ord_ev2 = OrderedL2ToL1Message::new(2, address!("35"), vec![5.into(), 6.into()]);
        let message1 = L2toL1MessageInfo::new(ord_ev1, address!("1234"));
        let message2 = L2toL1MessageInfo::new(ord_ev2, address!("1235"));

        assert_eq!(
            calculate_tx_gas_usage(vec![message1, message2], 2, 2, Some(2), 1),
            77051
        )
    }
}
