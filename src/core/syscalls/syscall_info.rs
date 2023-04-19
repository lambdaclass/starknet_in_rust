use std::collections::HashMap;

use cairo_lang_casm::hints::Hint;
use cairo_rs::hint_processor::builtin_hint_processor::hint_code;
use cairo_rs::serde::deserialize_program::{ApTracking, FlowTrackingData, HintParams};

pub fn get_syscall_size_from_name(syscall_name: &str) -> usize {
    match syscall_name {
        "call_contract" => 7,
        "deploy" => 9,
        "emit_event" => 5,
        "get_block_number" => 2,
        "get_block_timestamp" => 2,
        "get_caller_address" => 2,
        "get_contract_address" => 2,
        "get_sequencer_address" => 2,
        "get_tx_info" => 2,
        "get_tx_signature" => 3,
        "library_call" => 7,
        "library_call_l1_handler" => 7,
        "send_message_to_l1" => 4,
        "storage_read" => 3,
        "storage_write" => 3,
        "replace_class" => 2,
        _ => unreachable!(),
    }
}

#[allow(dead_code)]
pub(crate) fn hint_to_hint_params(hint: Hint) -> HintParams {
    match hint {
        Hint::AllocSegment { dst } => {
            let flow_tracking_data = FlowTrackingData {
                ap_tracking: ApTracking {
                    group: 0,
                    offset: dst.offset as usize,
                },
                reference_ids: HashMap::new(),
            };
            HintParams {
                code: hint_code::ADD_SEGMENT.to_string(),
                accessible_scopes: vec![
                    String::from("starkware.cairo.common.alloc"),
                    String::from("starkware.cairo.common.alloc.alloc"),
                ],
                flow_tracking_data,
            }
        }
        Hint::TestLessThan { .. } => {
            todo!()
        }
        Hint::SquareRoot { value, dst } => {
            drop(value); // todo
            drop(dst); // todo
            let flow_tracking_data = FlowTrackingData {
                ap_tracking: ApTracking::new(),
                reference_ids: HashMap::new(),
            };
            HintParams {
                code: hint_code::IS_QUAD_RESIDUE.to_string(),
                accessible_scopes: vec![],
                flow_tracking_data,
            }
        }

        //     Hint::TestLessThanOrEqual { lhs, rhs, dst } => todo!(),
        //     Hint::DivMod {
        //         lhs,
        //         rhs,
        //         quotient,
        //         remainder,
        //     } => todo!(),
        //     Hint::Uint256DivMod {
        //         dividend_low,
        //         dividend_high,
        //         divisor_low,
        //         divisor_high,
        //         quotient0,
        //         quotient1,
        //         divisor0,
        //         divisor1,
        //         extra0,
        //         extra1,
        //         remainder_low,
        //         remainder_high,
        //     } => todo!(),
        //     Hint::LinearSplit {
        //         value,
        //         scalar,
        //         max_x,
        //         x,
        //         y,
        //     } => todo!(),
        //     Hint::AllocFelt252Dict { segment_arena_ptr } => todo!(),
        //     Hint::Felt252DictRead {
        //         dict_ptr,
        //         key,
        //         value_dst,
        //     } => todo!(),
        //     Hint::Felt252DictWrite {
        //         dict_ptr,
        //         key,
        //         value,
        //     } => todo!(),
        //     Hint::GetSegmentArenaIndex {
        //         dict_end_ptr,
        //         dict_index,
        //     } => todo!(),
        //     Hint::InitSquashData {
        //         dict_accesses,
        //         ptr_diff,
        //         n_accesses,
        //         big_keys,
        //         first_key,
        //     } => todo!(),
        //     Hint::GetCurrentAccessIndex { range_check_ptr } => todo!(),
        //     Hint::ShouldSkipSquashLoop { should_skip_loop } => todo!(),
        //     Hint::GetCurrentAccessDelta { index_delta_minus1 } => todo!(),
        //     Hint::ShouldContinueSquashLoop { should_continue } => todo!(),
        //     Hint::AssertCurrentAccessIndicesIsEmpty => todo!(),
        //     Hint::AssertAllAccessesUsed { n_used_accesses } => todo!(),
        //     Hint::AssertAllKeysUsed => todo!(),
        //     Hint::GetNextDictKey { next_key } => todo!(),
        //     Hint::AssertLtAssertValidInput { a, b } => todo!(),
        Hint::AssertLeFindSmallArcs {
            range_check_ptr,
            a,
            b,
        } => {
            drop(range_check_ptr);
            drop(a);
            drop(b);
            let flow_tracking_data = FlowTrackingData {
                ap_tracking: ApTracking::new(),
                reference_ids: HashMap::new(),
            };
            HintParams {
                code: hint_code::ASSERT_LE_FELT.to_string(),
                accessible_scopes: vec![],
                flow_tracking_data,
            }
        }
        //     Hint::AssertLeIsFirstArcExcluded {
        //         skip_exclude_a_flag,
        //     } => todo!(),
        //     Hint::AssertLeIsSecondArcExcluded {
        //         skip_exclude_b_minus_a,
        //     } => todo!(),
        //     Hint::AssertLeAssertThirdArcExcluded => todo!(),
        //     Hint::RandomEcPoint { x, y } => todo!(),
        //     Hint::FieldSqrt { val, sqrt } => todo!(),
        //     Hint::SystemCall { system } => todo!(),
        //     Hint::DebugPrint { start, end } => todo!(),
        //     Hint::AllocConstantSize { size, dst } => todo!(),
        //     Hint::SetBlockNumber { value } => todo!(),
        //     Hint::SetBlockTimestamp { value } => todo!(),
        //     Hint::SetCallerAddress { value } => todo!(),
        //     Hint::SetContractAddress { value } => todo!(),
        //     Hint::SetSequencerAddress { value } => todo!(),
        _ => todo!(),
    }
}
