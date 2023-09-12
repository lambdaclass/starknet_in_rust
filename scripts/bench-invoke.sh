#!/usr/bin/env sh
hyperfine -N -w 3 -r 5 \
	    -n "starknet_in_rust read/write storage 10k without deploy" "./target/release/invoke"
