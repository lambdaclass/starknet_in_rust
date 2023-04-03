#!/usr/bin/env sh
hyperfine -w 3 -r 5 \
	    -n "cairo-lang (CPython) read/write storage 10k with deploy" "pytest bench_integration.py::test_invoke" \
	    -n "starknet_in_rust read/write storage 10k with deploy" "./target/release/deploy_invoke"
