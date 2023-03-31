#!/usr/bin/env sh
hyperfine -w 3 -r 5 \
	    -n "cairo-lang (CPython) deploy 10k" "pytest bench_integration.py::test_deploy" \
	    -n "starknet_in_rust deploy 10k" "cargo run --bin deploy --release"
