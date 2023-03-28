import os

import pytest
import pytest_asyncio

from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.testing.starknet import Starknet

CONTRACT_FILE = os.path.join(os.path.dirname(__file__), "test.cairo")

@pytest_asyncio.fixture
async def starknet() -> Starknet:
    return await Starknet.empty()

@pytest_asyncio.fixture
async def contract(starknet: Starknet) -> StarknetContract:
    return await starknet.deploy(source=CONTRACT_FILE)

@pytest.mark.asyncio
async def test_invoke(contract: StarknetContract):
    for i in range(0, 1):
        await contract.fib(first_element=1, second_element=1, n=15000).execute()
