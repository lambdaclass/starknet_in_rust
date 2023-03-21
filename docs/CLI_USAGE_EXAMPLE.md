# CLI Usage Example

For this example we will be using the contract [example_contract.cairo](../contract_execution_examples/example_contract.cairo)

## Prerequisites

- Having cairo-lang installed
- Having built starknet-rs using `cargo build --release`

## Steps

### Start up the server

```=bash
target/release/starknet-rs starknet_in_rust
```

### Compile the contract using starknet-compile

```=bash
starknet-compile contract_execution_examples/example_contract.cairo --output example_contract.json --abi example_contract_abi.json
```

### Declare the contract

```=bash
target/release/starknet-rs declare --contract example_contract.json
```

This will return the following data:

```=bash
Contract class hash: 0x585725368e79f1757ffeb4baa04548c314d652993c6c9e726bdd754e78d8c7a
Transaction hash: 0x3826a3cf201d397a7929e6cc651e065097adb87e3759079e851bdaa38e74421
```

### Deploy the contract

Pass the class_hash obtained when declaring the contract to deploy

```=bash
target/release/starknet-rs deploy --class_hash 0x585725368e79f1757ffeb4baa04548c314d652993c6c9e726bdd754e78d8c7a

```

This will return the following data:

```=bash
Invoke transaction for contract deployment was sent.
Contract address: 0x76c1d19703043d7ef9ff3450db76e0b31787b57b06d89ad97cbfddeee3decd1
Transaction hash: 0x13699fd1061f0668fc44bc96c348626abfff406010eef89624b3ddae6e02776
```

### Invoke a contract method

 Invoke the method `increase_balance` with the input 1234 in order to update the `balance` storage variable

```=bash
target/release/starknet-rs invoke \
    --address 0x76c1d19703043d7ef9ff3450db76e0b31787b57b06d89ad97cbfddeee3decd1 \
    --abi example_contract_abi.json \
    --function increase_balance \
    --inputs 1234
```

The result should look like this:

```=bash
Invoke transaction was sent.
Contract address: 0x76c1d19703043d7ef9ff3450db76e0b31787b57b06d89ad97cbfddeee3decd1
Transaction hash: 0x3719bf767be2a666f3c23e3cf97accafab4cfc528c20cd3a42655c35818be55
```

### Call a contract method

Call the method `get_balance` in order to query the updated `balance`

```=bash
target/release/starknet-rs call \
    --address 0x76c1d19703043d7ef9ff3450db76e0b31787b57b06d89ad97cbfddeee3decd1 \
    --abi example_contract_abi.json \
    --function get_balance
```

This will return the updated balance:

```=bash
1234
```
