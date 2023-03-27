#!/usr/bin/env sh
hyperfine \
	    -n "cairo-lang" "pytest bench_integration.py" \
	    -n "starknet_in_rust" "cargo test testing::bench_integration::test_invoke --release"

