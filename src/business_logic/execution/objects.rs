use num_bigint::BigInt;

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
        }
    }
}
