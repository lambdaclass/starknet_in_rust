# StarkNet-DevNet guide

## Links
- Documentation: https://shard-labs.github.io/starknet-devnet/
- Available commands: https://shard-labs.github.io/starknet-devnet/docs/guide/interaction
- Repository: https://github.com/Shard-Labs/starknet-devnet

## Requirements
- `Python 3.9`

## Setup
- Create virtual environment:
  ```
  python3.9 -m venv ~/starknet-devnet-env
  ```
- Activate virtual environment:
  ```
  source ~/starknet-devnet-env/bin/activate
  ```
- Install starknet-devnet, [some previous steps are required and are explained here](https://shard-labs.github.io/starknet-devnet/):
  ```
  pip install starknet-devnet
  ```
- Run devnet: 
    ```
    starknet-devnet
    ```
- In another terminal, [setup the environment](https://docs.starknet.io/documentation/getting_started/account_setup/):
    ```
    export STARKNET_NETWORK=alpha-goerli
    export STARKNET_WALLET=starkware.starknet.wallets.open_zeppelin.OpenZeppelinAccount
    ```

## Test
- Create an account:
    ```
    starknet new_account --feeder_gateway_url http://127.0.0.1:5050/ --gateway_url http://127.0.0.1:5050/21:03
    ```

- Add some funds to the account:
    ```
    sh scripts/add-funds.sh <your-new-address>
    ```
    
- Deploy the account:
    ```
    starknet deploy_account --feeder_gateway_url http://127.0.0.1:5050/ --gateway_url http://127.0.0.1:5050/
    ```

- Compile a contract:
    ```
    starknet-compile fibonacci.cairo \
        --output fibonacci_compiled.json \
        --abi fibonacci_abi.json
    ```

- Declare the contract:
    ```
    starknet declare --contract fibonacci_compiled.json --feeder_gateway_url http://127.0.0.1:5050/ --gateway_url http://127.0.0.1:5050/
    ```

- Deploy the contract:
    ```
    starknet deploy --class_hash 0x284536ad7de8852cc9101133f7f7670834084d568610335c94da1c4d9ce4be6 --feeder_gateway_url http://127.0.0.1:5050/ --gateway_url http://127.0.0.1:5050/
    ```

- Invoke the contract:
    ```
    starknet invoke --address 0x05a24faff7ca35369ae72e031567bcfcab00e959cce41392bab3b5d26752f810 --function fib --inputs 1 1 10 --abi fibonacci_abi.json  --feeder_gateway_url http://127.0.0.1:5050/ --gateway_url http://127.0.0.1:5050/
    ```
-  See the result:
    ```
    starknet get_transaction_trace --hash 0x614526ed889c1223b6dbfd370386f74ab537bbfa5dc463bff3b86245cc59290 --feeder_gateway_url http://127.0.0.1:5050/ --gateway_url http://127.0.0.1:5050/
    ```

## Notes
In case you turn off the devnet server, the state will become wrong. You need to run `rm -rf ~/.starknet_accounts` in order to properly restart the state. 
