#!/usr/bin/env python3

import json
import sys


# Read JSON program.
data = json.load(sys.stdin)

# Replace ABI items' type from `function` to `regular`.
for item in data['abi']:
    if item['type'] == 'function':
        item['type'] = 'regular'

# Write JSON program.
json.dump(data, sys.stdout, indent=4 * ' ')
