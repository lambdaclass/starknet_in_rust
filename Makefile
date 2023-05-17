.PHONY: build check clean clippy compile-cairo compile-starknet coverage deps test heaptrack check-python-version compile-abi

OS := $(shell uname)
ifeq ($(OS), Darwin)
	CFLAGS  += -I/opt/homebrew/opt/gmp/include
	LDFLAGS += -L/opt/homebrew/opt/gmp/lib
endif


CAIRO_SOURCES=$(wildcard cairo_programs/*.cairo)
CAIRO_TARGETS=$(patsubst %.cairo,%.json,$(CAIRO_SOURCES))

STARKNET_SOURCES=$(wildcard starknet_programs/*.cairo)
STARKNET_TARGETS=$(patsubst %.cairo,%.json,$(STARKNET_SOURCES))

BUILTIN_SOURCES=$(wildcard starknet_programs/*.cairo)
BUILTIN_TARGETS=$(patsubst %.cairo,%.json,$(BUILTIN_SOURCES))

STARKNET_COMPILE:=cairo/target/release/starknet-compile
STARKNET_SIERRA_COMPILE:=cairo/target/release/starknet-sierra-compile


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

compile-cairo: $(CAIRO_TARGETS)
compile-starknet: $(STARKNET_TARGETS)

cairo_programs/%.json: cairo_programs/%.cairo
	. starknet-venv/bin/activate && cd cairo_programs/ && cairo-compile $(shell grep "^// @compile-flags += .*$$" $< | cut -c 22-) ../$< --output ../$@ || rm ../$@


starknet_programs/%.json: starknet_programs/%.cairo
	. starknet-venv/bin/activate && \
	cd starknet_programs/ && \
	starknet-compile $(shell grep "^// @compile-flags += .*$$" $< | cut -c 22-) \
	../$< \
	--output ./$*.json \
	--abi ./$*_abi.json \
	|| rm ./$*.json ./$*_abi.json
# Compiles .cairo files into .json files. if the command fails, then it removes all of the .json files


# ======================
# Test Cairo 1 Contracts
# ======================

CAIRO_1_CONTRACTS_TEST_DIR=starknet_programs/cairo1
CAIRO_1_CONTRACTS_TEST_CAIRO_FILES:=$(wildcard $(CAIRO_1_CONTRACTS_TEST_DIR)/*.cairo)
COMPILED_SIERRA_CONTRACTS:=$(patsubst $(CAIRO_1_CONTRACTS_TEST_DIR)/%.cairo, $(CAIRO_1_CONTRACTS_TEST_DIR)/%.json, $(CAIRO_1_CONTRACTS_TEST_CAIRO_FILES))
COMPILED_CASM_CONTRACTS:= $(patsubst $(CAIRO_1_CONTRACTS_TEST_DIR)/%.json, $(CAIRO_1_CONTRACTS_TEST_DIR)/%.casm, $(COMPILED_SIERRA_CONTRACTS))

$(CAIRO_1_CONTRACTS_TEST_DIR)/%.sierra: $(CAIRO_1_CONTRACTS_TEST_DIR)/%.cairo
	$(STARKNET_COMPILE) --allowed-libfuncs-list-name experimental_v0.1.0 $< $@

$(CAIRO_1_CONTRACTS_TEST_DIR)/%.casm: $(CAIRO_1_CONTRACTS_TEST_DIR)/%.sierra
	$(STARKNET_SIERRA_COMPILE) --allowed-libfuncs-list-name experimental_v0.1.0 $< $@


cairo-repo-dir = cairo

build-cairo-1-compiler: | $(cairo-repo-dir)

$(cairo-repo-dir):
	git clone --depth 1 -b v1.0.0-rc0 https://github.com/starkware-libs/cairo.git
	cd cairo; cargo b --release --bin starknet-compile --bin starknet-sierra-compile


# =================
# Normal rules.
# =================

build: compile-cairo compile-starknet
	cargo build --release --all

check: compile-cairo compile-starknet
	cargo check --all

deps: check-python-version build-cairo-1-compiler
	cargo install flamegraph --version 0.6.2
	cargo install cargo-llvm-cov --version 0.5.14
	python3 -m venv starknet-venv
	. starknet-venv/bin/activate && $(MAKE) deps-venv

clean:
	-rm -rf starknet-venv/
	-rm -f cairo_programs/*.json
	-rm -f cairo_programs/cairo_1_contracts/*.json
	-rm -f cairo_programs/cairo_1_contracts/*.casm
	-rm -f starknet_programs/*.json
	-rm -f tests/*.json
	-rm -rf cairo/

clippy: compile-cairo compile-starknet $(COMPILED_CASM_CONTRACTS)
	cargo clippy --all --all-targets -- -D warnings

test: compile-cairo compile-starknet $(COMPILED_CASM_CONTRACTS)
	cargo test

coverage: compile-cairo compile-starknet compile-abi $(COMPILED_CASM_CONTRACTS)
	cargo llvm-cov --ignore-filename-regex 'main.rs'
	cargo llvm-cov report --lcov --ignore-filename-regex 'main.rs' --output-path lcov.info

heaptrack:
	./scripts/heaptrack.sh

flamegraph: compile-cairo compile-starknet
	CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph --root --bench internals

