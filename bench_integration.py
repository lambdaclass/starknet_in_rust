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
    starknet = await Starknet.empty()
    for _ in range(runs):
        await starknet.deploy(source=CONTRACT_FILE)

@pytest.mark.asyncio
async def test_fibonacci():
    runs = 1000
    starknet = await Starknet.empty()
    contract = await starknet.deploy(source=FIBONACCI_FILE)
    for i in range(runs):
        call = await contract.fib(first_element=1, second_element=1, n=15000).execute()
        assert(call.result == (1885488015763367495828256465007039431853769505513107413590764748562946299654, ))
