import os

import pytest
import pytest_asyncio

from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.testing.starknet import Starknet

CONTRACT_FILE = os.path.join(os.path.dirname(__file__), "test.cairo")

@pytest.mark.asyncio
async def test_invoke():
    starknet = await Starknet.empty()
    contract = await starknet.deploy(source=CONTRACT_FILE)
    await contract.fib(first_element=1, second_element=1, n=15000).execute()
