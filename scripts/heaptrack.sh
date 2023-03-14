#!/bin/bash

declare -a tests=("fibonacci" 
                  "internals"
                  "storage"
                )

mkdir -p reports reports/heaptrack reports/heaptrack/outfile reports/heaptrack/analysis

for test in "${tests[@]}"
do
    FILE_PREFIX="heaptrack.${test}"
    OUTFILE="reports/heaptrack/outfile/${FILE_PREFIX}"
    ANALYSIS="reports/heaptrack/analysis/${FILE_PREFIX}"
    echo "Heaptracking ${test}"
    # Runs the process and starts the heaptrack.
     heaptrack -o "${OUTFILE}" "cargo" "test" "--test" "${test}"
    # Analyze the file.
    heaptrack -a "${OUTFILE}.gz" > ${ANALYSIS}.txt
    echo "Heaptracked ${test}"
done
