import os

import pytest
import pytest_asyncio

from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.testing.starknet import Starknet

# ACCOUNT_FILE = os.path.join(os.path.dirname(__file__), "../../starknet_programs/account_without_validation.cairo")
CONTRACT_FILE = os.path.join(os.path.dirname(__file__), "../../starknet_programs/first_contract.cairo")

@pytest_asyncio.fixture
async def starknet() -> Starknet:
    return await Starknet.empty()

@pytest_asyncio.fixture
async def contract(starknet: Starknet) -> StarknetContract:
    return await starknet.deploy(source=CONTRACT_FILE)

# @pytest_asyncio.fixture
# async def account(starknet: Starknet) -> StarknetContract:
#     return await starknet.deploy(source=ACCOUNT_FILE)

@pytest.mark.asyncio
async def test_invoke1000(contract: StarknetContract):
    # contract_address, selector: felt, calldata_len: felt, calldata: felt*
    # call_info = await account.__execute__(contract_address=contract.contract_address, selector=0x112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9, calldata=[1, 1, 10]).execute()
    for i in range(1, 1001):
        await contract.increase_balance(amount=10).execute()
        call_info = await contract.get_balance().execute()
        assert call_info.result == (10 * i,)

@pytest.mark.asyncio
async def test_invoke5000(contract: StarknetContract):
    # contract_address, selector: felt, calldata_len: felt, calldata: felt*
    # call_info = await account.__execute__(contract_address=contract.contract_address, selector=0x112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9, calldata=[1, 1, 10]).execute()
    for i in range(1, 5001):
        await contract.increase_balance(amount=10).execute()
        call_info = await contract.get_balance().execute()
        assert call_info.result == (10 * i,)

@pytest.mark.asyncio
async def test_invoke10000(contract: StarknetContract):
    # contract_address, selector: felt, calldata_len: felt, calldata: felt*
    # call_info = await account.__execute__(contract_address=contract.contract_address, selector=0x112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9, calldata=[1, 1, 10]).execute()
    for i in range(1, 10001):
        await contract.increase_balance(amount=10).execute()
        call_info = await contract.get_balance().execute()
        assert call_info.result == (10 * i,)
