import os

import pytest
import pytest_asyncio
from starkware.starknet.compiler.compile import compile_starknet_files
from starkware.starknet.testing.starknet import StarknetState
from starkware.starknet.services.api.contract_class import ContractClass
CONTRACT_FILE = os.path.join(os.path.dirname(__file__), "starknet_programs/first_contract.json")
FIBONACCI_FILE = os.path.join(os.path.dirname(__file__), "starknet_programs/fibonacci.json")


@pytest.mark.asyncio
async def test_invoke():
    runs = 10000
    starknet = await StarknetState.empty()
    json_program = open(CONTRACT_FILE).read()
    contract_class = ContractClass.loads(json_program)
    contract_address, _ = await starknet.deploy(contract_class=contract_class, constructor_calldata=[])
    for i in range(runs):
        # take into account that you need to comment verify_version()
        # from cairo-lang in order to be able to run the selectors below
        # because invoke_raw inserts a default version=0 that throws an
        # error.
        res_1 = await starknet.invoke_raw(contract_address=contract_address, selector="increase_balance", calldata=[1000], max_fee=0)
        res_2 = await starknet.invoke_raw(contract_address=contract_address, selector="get_balance", calldata=[], max_fee=0)
        assert(res_2.call_info.retdata == [i*1000 + 1000])

@pytest.mark.asyncio
async def test_deploy():
    runs = 100
    starknet = await StarknetState.empty()
    json_program = open(CONTRACT_FILE).read()
    contract_class = ContractClass.loads(json_program)
    for i in range(runs):
        contract_address, _ = await starknet.deploy(contract_class=contract_class, constructor_calldata=[], contract_address_salt=i)

@pytest.mark.asyncio
async def test_fibonacci():
    runs = 1000
    starknet = await StarknetState.empty()
    json_program = open(FIBONACCI_FILE).read()
    contract_class = ContractClass.loads(json_program)
    contract_address, _ = await starknet.deploy(contract_class=contract_class, constructor_calldata=[])
    for i in range(runs):
        call = await starknet.invoke_raw(contract_address=contract_address, selector="fib", calldata=[1, 1, 1000], max_fee=0)
        assert(call.call_info.retdata == [222450955505511890955301767713383614666194461405743219770606958667979327682])
