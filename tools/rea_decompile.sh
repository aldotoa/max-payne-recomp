#!/bin/bash
# Usage: rea_decompile.sh <file> <procedure-or-address>  -> prints pseudo-code
npx --yes rea-agents@6.5.0 decompile "$1" "$2" --provider ghidra --format json 2>/dev/null | python3 -I -c '
import json,sys
d=json.load(sys.stdin)
n=d.get("normalized_result")
if not isinstance(n,str):
    n=(d.get("raw_result") or {}).get("value") or json.dumps(d)[:2000]
print(n)'
