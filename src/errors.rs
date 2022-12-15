pub enum StarknetError {
    IteratorNotEmpty,
    ListIsEmpty,
    ShouldBeNone(String),
    UnexpectedConstructorRetdata,
    WriteArg,
    KeyNotFound,
    IteratorEmpty,
}
