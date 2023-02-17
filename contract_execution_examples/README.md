## Running simple contracts

- First run '''make deps''' in order to setup the environment.

- Add your contract to this directory. 

    - Remember that in order to call functions you must use the *external* decorator.

    - You also must add *%lang starknet* at the beggining of the contract.


- compile the contract:
    - source starknet-venv/bin/activate

    - starknet-compile your_contract.cairo --output your_contract.json

- 