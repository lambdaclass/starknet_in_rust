use num_bigint::BigInt;
use num_traits::Zero;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedEvent {
    #[allow(unused)] // TODO: remove once used
    order: u64,
    #[allow(unused)] // TODO: remove once used
    keys: Vec<BigInt>,
    #[allow(unused)] // TODO: remove once used
    data: Vec<BigInt>,
}
#[derive(Clone)]
pub(crate) struct TransactionExecutionContext {
    pub(crate) n_emitted_events: u64,
    pub(crate) version: usize,
    pub(crate) account_contract_address: BigInt,
    pub(crate) max_fee: BigInt,
    pub(crate) transaction_hash: BigInt,
    pub(crate) signature: Vec<BigInt>,
    pub(crate) nonce: BigInt,
    pub(crate) n_sent_messages: usize,
}

impl OrderedEvent {
    pub fn new(order: u64, keys: Vec<BigInt>, data: Vec<BigInt>) -> Self {
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
            n_sent_messages: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedL2ToL1Message {
    pub(crate) _order: usize,
    pub(crate) _to_address: usize,
    pub(crate) _payload: Vec<BigInt>,
}

impl OrderedL2ToL1Message {
    pub fn new(_order: usize, _to_address: usize, _payload: Vec<BigInt>) -> Self {
        OrderedL2ToL1Message {
            _order,
            _to_address,
            _payload,
        }
    }
}
