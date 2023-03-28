#!/usr/bin/env sh
hyperfine \
	    -n "cairo-lang 1k" "pytest bench_integration.py::test_invoke1000" \
	    -n "starknet_in_rust 1k" "cargo test testing::bench_integration::test_invoke --release"
