use felt::{felt_str, Felt};
use lazy_static::lazy_static;
use num_traits::Zero;

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
    /// Value generated from `get_selector_from_name('constructor')`.
    pub static ref CONSTRUCTOR_ENTRY_POINT_SELECTOR: Felt =
        felt_str!("1159040026212278395030414237414753050475174923702621880048416706425641521556");
    pub static ref DEFAULT_ENTRY_POINT_SELECTOR: Felt = Felt::zero();
    pub static ref EXECUTE_ENTRY_POINT_SELECTOR: Felt =
        felt_str!("617075754465154585683856897856256838130216341506379215893724690153393808813");

    /// Value generated from `get_selector_from_name('__validate_deploy__')`.
    pub static ref VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR: Felt =
        felt_str!("1554466106298962091002569854891683800203193677547440645928814916929210362005");
}
