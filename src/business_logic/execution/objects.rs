use num_bigint::BigInt;
use num_traits::Zero;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedEvent {
    #[allow(unused)] // TODO: remove once used
    order: u32,
    #[allow(unused)] // TODO: remove once used
    keys: Vec<BigInt>,
    #[allow(unused)] // TODO: remove once used
    data: Vec<BigInt>,
}

pub(crate) struct TransactionExecutionContext {
    pub(crate) n_emitted_events: u32,
    pub(crate) version: usize,
    pub(crate) account_contract_address: BigInt,
    pub(crate) max_fee: BigInt,
    pub(crate) transaction_hash: BigInt,
    pub(crate) signature: Vec<BigInt>,
    pub(crate) nonce: BigInt,
}

impl OrderedEvent {
    pub fn new(order: u32, keys: Vec<BigInt>, data: Vec<BigInt>) -> Self {
        OrderedEvent { order, keys, data }
    }
}

impl TransactionExecutionContext {
    pub fn new() -> Self {
        TransactionExecutionContext {
            n_emitted_events: 0,
            account_contract_address: BigInt::zero(),
            max_fee: BigInt::zero(),
            nonce: BigInt::zero(),
            signature: Vec::new(),
            transaction_hash: BigInt::zero(),
            version: 0,
        }
    }
}
