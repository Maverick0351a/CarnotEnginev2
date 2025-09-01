# NOTE: Placeholder canonicalization; Task A2 replaces with strict RFC 8785.
import json

def canonicalize(obj) -> bytes:
    return json.dumps(obj, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
