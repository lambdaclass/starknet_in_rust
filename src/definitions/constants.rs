use felt::Felt;
use lazy_static::lazy_static;
use num_traits::{Num, Zero};

pub(crate) const L2_TO_L1_MSG_HEADER_SIZE: usize = 3;
pub(crate) const L1_TO_L2_MSG_HEADER_SIZE: usize = 5;
pub(crate) const DEPLOYMENT_INFO_SIZE: usize = 2;
pub(crate) const CONSUMED_MSG_TO_L2_N_TOPICS: usize = 3;
pub(crate) const LOG_MSG_TO_L1_N_TOPICS: usize = 2;
pub(crate) const N_DEFAULT_TOPICS: usize = 1; // Events have one default topic.
pub(crate) const CONSUMED_MSG_TO_L2_ENCODED_DATA_SIZE: usize =
    (L1_TO_L2_MSG_HEADER_SIZE + 1) - CONSUMED_MSG_TO_L2_N_TOPICS;

pub(crate) const LOG_MSG_TO_L1_ENCODED_DATA_SIZE: usize =
    (L2_TO_L1_MSG_HEADER_SIZE + 1) - LOG_MSG_TO_L1_N_TOPICS;

pub const TRANSACTION_VERSION: u64 = 1;

lazy_static! {
    pub static ref DEFAULT_ENTRY_POINT_SELECTOR: Felt = Felt::zero();
    pub static ref EXECUTE_ENTRY_POINT_SELECTOR: Felt = Felt::from_str_radix(
        "617075754465154585683856897856256838130216341506379215893724690153393808813",
        10,
    )
    .unwrap();
}
