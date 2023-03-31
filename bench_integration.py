import os

import pytest
import pytest_asyncio

from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.testing.starknet import Starknet

CONTRACT_FILE = os.path.join(os.path.dirname(__file__), "starknet_programs/first_contract.cairo")

@pytest.mark.asyncio
async def test_invoke():
    runs = 1000
    starknet = await Starknet.empty()
    contract = await starknet.deploy(source=CONTRACT_FILE)
    for _ in range(runs):
        await contract.increase_balance(amount=1000).execute()
        await contract.get_balance().execute()

@pytest.mark.asyncio
async def test_deploy():
    runs = 10
    starknet = await Starknet.empty()
    for _ in range(runs):
        contract = await starknet.deploy(source=CONTRACT_FILE)
