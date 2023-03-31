import os

import pytest
import pytest_asyncio

from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.testing.starknet import Starknet

CONTRACT_FILE = os.path.join(os.path.dirname(__file__), "starknet_programs/first_contract.cairo")
FIBONACCI_FILE = os.path.join(os.path.dirname(__file__), "starknet_programs/fibonacci.cairo")


@pytest.mark.asyncio
async def test_invoke():
    runs = 10
    starknet = await Starknet.empty()
    contract = await starknet.deploy(source=CONTRACT_FILE)
    for i in range(runs):
        await contract.increase_balance(amount=1000).execute()
        call = await contract.get_balance().execute()
        assert(call.result == (i*1000 + 1000, ))

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
