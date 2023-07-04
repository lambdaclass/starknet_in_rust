.PHONY: build check clean clippy compile-cairo compile-starknet coverage deps test heaptrack check-python-version compile-abi

export PATH:=$(shell pyenv root)/shims:$(PATH)
export PYENV_VERSION=3.9

OS := $(shell uname)
ifeq ($(OS), Darwin)
	export CFLAGS  += -I/opt/homebrew/opt/gmp/include
	export LDFLAGS += -L/opt/homebrew/opt/gmp/lib
endif


CAIRO_SOURCES=$(wildcard cairo_programs/*.cairo)
CAIRO_TARGETS=$(patsubst %.cairo,%.json,$(CAIRO_SOURCES))
CAIRO_ABI_TARGETS=$(patsubst %.cairo,%_abi.json,$(CAIRO_SOURCES))

STARKNET_SOURCES=$(wildcard starknet_programs/*.cairo)
STARKNET_TARGETS=$(patsubst %.cairo,%.json,$(STARKNET_SOURCES))
STARKNET_ABI_TARGETS=$(patsubst %.cairo,%_abi.json,$(STARKNET_SOURCES))

BUILTIN_SOURCES=$(wildcard starknet_programs/*.cairo)
BUILTIN_TARGETS=$(patsubst %.cairo,%.json,$(BUILTIN_SOURCES))

STARKNET_COMPILE_CAIRO_1:=cairo1/bin/starknet-compile
STARKNET_SIERRA_COMPILE_CAIRO_1:=cairo1/bin/starknet-sierra-compile

STARKNET_COMPILE_CAIRO_2:=cairo2/bin/starknet-compile
STARKNET_SIERRA_COMPILE_CAIRO_2:=cairo2/bin/starknet-sierra-compile

#
# VENV rules.
#

deps-venv:
	pip install \
		fastecdsa \
		typeguard==2.13.0 \
		openzeppelin-cairo-contracts==0.6.1 \
		maturin \
		cairo-lang==0.11 \
		"urllib3 <=1.26.15"

compile-cairo: $(CAIRO_TARGETS) $(CAIRO_ABI_TARGETS)
compile-starknet: $(STARKNET_TARGETS) $(STARKNET_ABI_TARGETS)

cairo_programs/%.json cairo_programs/%_abi.json: cairo_programs/%.cairo
	. starknet-venv/bin/activate && cd cairo_programs/ && cairo-compile $(shell grep "^// @compile-flags += .*$$" $< | cut -c 22-) ../$< --output ../$@ || rm ../$@

starknet_programs/%.json starknet_programs/%_abi.json: starknet_programs/%.cairo
	. starknet-venv/bin/activate && \
	cd starknet_programs/ && \
	starknet-compile $(shell grep "^// @compile-flags += .*$$" $< | cut -c 22-) \
	../$< \
	--no_debug_info \
	--output ./$*.json \
	--abi ./$*_abi.json \
	|| rm ./$*.json ./$*_abi.json
# Compiles .cairo files into .json files. if the command fails, then it removes all of the .json files

# ======================
# Test Cairo 1 Contracts
# ======================

CAIRO_1_CONTRACTS_TEST_DIR=starknet_programs/cairo1
CAIRO_1_CONTRACTS_TEST_CAIRO_FILES:=$(wildcard $(CAIRO_1_CONTRACTS_TEST_DIR)/*.cairo)
CAIRO_1_COMPILED_SIERRA_CONTRACTS:=$(patsubst $(CAIRO_1_CONTRACTS_TEST_DIR)/%.cairo, $(CAIRO_1_CONTRACTS_TEST_DIR)/%.sierra, $(CAIRO_1_CONTRACTS_TEST_CAIRO_FILES))
CAIRO_1_COMPILED_CASM_CONTRACTS:= $(patsubst $(CAIRO_1_CONTRACTS_TEST_DIR)/%.sierra, $(CAIRO_1_CONTRACTS_TEST_DIR)/%.casm, $(CAIRO_1_COMPILED_SIERRA_CONTRACTS))

$(CAIRO_1_CONTRACTS_TEST_DIR)/%.sierra: $(CAIRO_1_CONTRACTS_TEST_DIR)/%.cairo
	$(STARKNET_COMPILE_CAIRO_1) --allowed-libfuncs-list-name experimental_v0.1.0 $< $@

$(CAIRO_1_CONTRACTS_TEST_DIR)/%.casm: $(CAIRO_1_CONTRACTS_TEST_DIR)/%.sierra
	$(STARKNET_SIERRA_COMPILE_CAIRO_1) --allowed-libfuncs-list-name experimental_v0.1.0 $< $@


cairo-repo-1-dir = cairo1
cairo-repo-1-dir-macos = cairo1-macos

build-cairo-1-compiler-macos: | $(cairo-repo-1-dir-macos)

$(cairo-repo-1-dir-macos):
	curl -L -o cairo-1.1.1.tar https://github.com/starkware-libs/cairo/releases/download/v1.1.1/release-aarch64-apple-darwin.tar \
	&& tar -xzvf cairo-1.1.1.tar \
	&& mv cairo/ cairo1/

build-cairo-1-compiler: | $(cairo-repo-1-dir)

$(cairo-repo-1-dir):
	curl -L -o cairo-1.1.1.tar https://github.com/starkware-libs/cairo/releases/download/v1.1.1/release-x86_64-unknown-linux-musl.tar.gz \
	&& tar -xzvf cairo-1.1.1.tar \
	&& mv cairo/ cairo1/

# ======================
# Test Cairo 2 Contracts
# ======================

CAIRO_2_CONTRACTS_TEST_DIR=starknet_programs/cairo2
CAIRO_2_CONTRACTS_TEST_CAIRO_FILES:=$(wildcard $(CAIRO_2_CONTRACTS_TEST_DIR)/*.cairo)
CAIRO_2_COMPILED_SIERRA_CONTRACTS:=$(patsubst $(CAIRO_2_CONTRACTS_TEST_DIR)/%.cairo, $(CAIRO_2_CONTRACTS_TEST_DIR)/%.sierra, $(CAIRO_2_CONTRACTS_TEST_CAIRO_FILES))
CAIRO_2_COMPILED_CASM_CONTRACTS:= $(patsubst $(CAIRO_2_CONTRACTS_TEST_DIR)/%.sierra, $(CAIRO_2_CONTRACTS_TEST_DIR)/%.casm, $(CAIRO_2_COMPILED_SIERRA_CONTRACTS))

$(CAIRO_2_CONTRACTS_TEST_DIR)/%.sierra: $(CAIRO_2_CONTRACTS_TEST_DIR)/%.cairo
	$(STARKNET_COMPILE_CAIRO_2) $< $@

$(CAIRO_2_CONTRACTS_TEST_DIR)/%.casm: $(CAIRO_2_CONTRACTS_TEST_DIR)/%.sierra
	$(STARKNET_SIERRA_COMPILE_CAIRO_2) $< $@


cairo-repo-2-dir = cairo2
cairo-repo-2-dir-macos = cairo2-macos

build-cairo-2-compiler-macos: | $(cairo-repo-2-dir-macos)

$(cairo-repo-2-dir-macos):
	curl -L -o cairo-2.0.0.tar https://github.com/starkware-libs/cairo/releases/download/v2.0.0/release-aarch64-apple-darwin.tar \
	&& tar -xzvf cairo-2.0.0.tar \
	&& mv cairo/ cairo2/

build-cairo-2-compiler: | $(cairo-repo-2-dir)

$(cairo-repo-2-dir):
	curl -L -o cairo-2.0.0.tar https://github.com/starkware-libs/cairo/releases/download/v2.0.0/release-x86_64-unknown-linux-musl.tar.gz \
	&& tar -xzvf cairo-2.0.0.tar \
	&& mv cairo/ cairo2/


# =================
# Normal rules.
# =================

build: compile-cairo compile-starknet
	cargo build --release --all

check: compile-cairo compile-starknet
	cargo check --all --all-targets

deps: check-python-version build-cairo-2-compiler build-cairo-1-compiler
	cargo install flamegraph --version 0.6.2
	cargo install cargo-llvm-cov --version 0.5.14
	python3.9 -m venv starknet-venv
	. starknet-venv/bin/activate && $(MAKE) deps-venv

deps-macos: check-python-version build-cairo-2-compiler-macos build-cairo-1-compiler-macos
	cargo install flamegraph --version 0.6.2
	cargo install cargo-llvm-cov --version 0.5.14
	python3.9 -m venv starknet-venv
	. starknet-venv/bin/activate && $(MAKE) deps-venv

clean:
	-rm -rf starknet-venv/
	-rm -f cairo_programs/*.json
	-rm -f cairo_programs/cairo_1_contracts/*.json
	-rm -f cairo_programs/cairo_1_contracts/*.casm
	-rm -f starknet_programs/*.json
	-rm -f starknet_programs/cairo1/*.casm
	-rm -f starknet_programs/cairo1/*.sierra
	-rm -f starknet_programs/cairo2/*.casm
	-rm -f starknet_programs/cairo2/*.sierra
	-rm -f tests/*.json
	-rm -rf cairo1/
	-rm -rf cairo2/
	-rm -rf cairo-2.0.0.tar
	-rm -rf cairo-1.1.1.tar

clippy: compile-cairo compile-starknet $(CAIRO_1_COMPILED_CASM_CONTRACTS) $(CAIRO_2_COMPILED_CASM_CONTRACTS)
	cargo clippy --all --all-targets -- -D warnings

test: compile-cairo compile-starknet $(CAIRO_1_COMPILED_CASM_CONTRACTS) $(CAIRO_1_COMPILED_SIERRA_CONTRACTS) $(CAIRO_2_COMPILED_CASM_CONTRACTS) $(CAIRO_2_COMPILED_SIERRA_CONTRACTS)
	echo "Cairo1 tests"
	cargo test --release --all --all-targets --features=cairo_1_tests
	echo "Cairo2 tests"
	cargo test --release --all --all-targets

coverage: compile-cairo compile-starknet compile-abi $(CAIRO_1_COMPILED_CASM_CONTRACTS) $(CAIRO_2_COMPILED_CASM_CONTRACTS)
	cargo +nightly llvm-cov --ignore-filename-regex 'main.rs' --release
	cargo +nightly llvm-cov report --lcov --ignore-filename-regex 'main.rs' --output-path lcov.info --release

heaptrack:
	./scripts/heaptrack.sh

flamegraph: compile-cairo compile-starknet
	CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --bench internals

benchmark: compile-cairo compile-starknet
	cargo build --release --all-targets
	./scripts/bench-invoke.sh
	./scripts/bench-deploy-invoke.sh
	./scripts/bench-fibonacci.sh
	./scripts/bench-deploy.sh
