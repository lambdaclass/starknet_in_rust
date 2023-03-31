#!/usr/bin/env sh
hyperfine -w 3 -r 5 \
	    -n "cairo-lang (CPython) read/write storage" "pytest bench_integration.py::test_invoke" \
	    -n "starknet_in_rust read/write storage without deploy" "cargo run --bin invoke --release"
