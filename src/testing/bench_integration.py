import os

import pytest
import pytest_asyncio

from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.testing.starknet import Starknet

ACCOUNT_FILE = os.path.join(os.path.dirname(__file__), "../../starknet_programs/account_without_validations.cairo")
CONTRACT_FILE = os.path.join(os.path.dirname(__file__), "../../starknet_programs/fibonacci.cairo")

@pytest_asyncio.fixture
async def starknet() -> Starknet:
    return await Starknet.empty()

@pytest_asyncio.fixture
async def contract(starknet: Starknet) -> StarknetContract:
    return await starknet.deploy(source=CONTRACT_FILE)

@pytest_asyncio.fixture
async def account(starknet: Starknet) -> StarknetContract:
    return await starknet.deploy(source=ACCOUNT_FILE)

@pytest.mark.asyncio
async def test_basic(contract: StarknetContract, account: StarknetContract, starknet: Starknet):
    print(starknet.__dir__)
    # contract_address, selector: felt, calldata_len: felt, calldata: felt*
    call_info = await account.__execute__(contract_address=contract.contract_address, selector=0x112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9, calldata=[1, 1, 10]).execute()
    assert call_info.result == (144,)
