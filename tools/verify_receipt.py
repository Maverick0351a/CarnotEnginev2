#!/usr/bin/env python3
import json, sys, base64, hashlib
from signet import jcs, merkle

def main(receipt_path, obs_path):
    r = json.load(open(receipt_path))
    obs = json.load(open(obs_path))
    # NOTE: This is a simplified verifier; Task A2/A4 will expand.
    raw = jcs.canonicalize(obs)
    leaf = merkle.leaf_hash(raw)
    print("leaf matches:", leaf.hex() == r["leafHash"])

if __name__ == "__main__":
    if len(sys.argv)<3:
        print("usage: verify_receipt.py <receipt.json> <observation.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
