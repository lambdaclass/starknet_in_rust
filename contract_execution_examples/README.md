## Running simple contracts

The idea of this small tutorial is to introduce how to run simple contracts using starknet_in_rust, specifically how to call *external* functions given a already declared (contract class defined in the starknet state) and deploy (a given instance of a contract class, with storage assigned to it) contract.

As declare and deploy transactions are currently WIP, we encapsulate all the fucntionality (declaring, deploying and executing a given entrypoint) in ```execute_contract.rs```.

## How to use

- First run ```make deps``` in order to setup the environment.

- Add your contract to this directory. 

    - Remember that in order to call functions you must use the *external* decorator.

    - You also must add ```%lang starknet``` at the beggining of the contract.


- Compile the contract:
    - ```source starknet-venv/bin/activate```
    - ```starknet-compile your_contract.cairo --output your_contract.json```

- Add a test for your contract calling ```test_contract``` passing:
    - Your compiled contract path
    - The entrypoint you are wanting to execute
    - The parameters needed in order to call that entrypoint
    - The expected returned value     
