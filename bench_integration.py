import os

import pytest
import pytest_asyncio

from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.testing.starknet import Starknet

CONTRACT_FILE = os.path.join(os.path.dirname(__file__), "starknet_programs/first_contract.cairo")

@pytest.mark.asyncio
async def test_invoke():
    runs = 10000
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

