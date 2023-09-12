#!/usr/bin/env sh
hyperfine -N -w 3 -r 5 \
	    -n "starknet_in_rust deploy 10k" "./target/release/deploy"
