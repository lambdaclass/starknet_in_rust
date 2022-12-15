use num_bigint::BigInt;

pub(crate) struct OrderedEvent {
    order: u32,
    keys: Vec<BigInt>,
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
