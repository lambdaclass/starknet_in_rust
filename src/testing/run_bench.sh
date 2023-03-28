#!/usr/bin/env sh
hyperfine \
	    -n "cairo-lang fib 15k" "pytest bench_integration.py::test_invoke" \
	    -n "starknet_in_rust fib 15k" "cargo test testing::bench_integration::test_invoke --release"
