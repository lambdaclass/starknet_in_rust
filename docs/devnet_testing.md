# Run starknet-devnet locally

#### Create a Python environment
```
python3.9 -m venv ~/starknet-devnet-env
source ~/starknet-devnet-env/bin/activate
```

#### Install starknet dependencies
```
brew install gmp
CFLAGS=-I/opt/homebrew/opt/gmp/include LDFLAGS=-L/opt/homebrew/opt/gmp/lib pip install fastecdsa
pip install starknet-devnet
```

#### Install dev dependencies
```
git clone --depth 1 --branch v0.4.6 git@github.com:Shard-Labs/starknet-devnet.git
cd starknet-devnet
./scripts/install_dev_tools.sh
```

#### Testing: Compile contracts & run tests
```
./scripts/compile_contracts.sh
poetry run pytest -s -v test # To run all tests with verbose mode
poetry run pytest test/<TEST_FILE> # To run a single test
```

# Workflow
In order to test how changes in the starknet codebase affect the `starknet-devnet`, you can install `starknet-rs-py` with
```
maturin develop
```
and then run the script `scripts/patch-devnet.sh` while in the devnet repo.
This will replace all uses of `starkware.starknet` with `starknet_rs_py`.

**Note**: this assumes a devnet version of v0.4.6, as specified in _Installing dev dependencies_
