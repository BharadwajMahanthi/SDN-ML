#!/usr/bin/env python3
import sys
import json

# Example: read Zeek-generated file or args
mac = sys.argv[1] if len(sys.argv) > 1 else "unknown"

result = {
    "mac": mac,
    "attack": "host_location_hijack",
    "confidence": 0.93,
    "model": "RandomForest"
}

# Zeek captures stdout
print(json.dumps(result))
sys.exit(0)
