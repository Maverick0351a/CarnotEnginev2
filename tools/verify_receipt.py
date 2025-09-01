#!/usr/bin/env python3
import json, sys, base64, hashlib
from signet import jcs, merkle

def main(receipt_path, obs_path):
    r = json.load(open(receipt_path))
    obs = json.load(open(obs_path))

    # Recompute raw_event_hash from provided observation
    can = jcs.canonicalize(obs)
    raw_event_hash = hashlib.sha256(can).hexdigest()

    # Pull context hashes from receipt if present; otherwise fall back to raw
    ctx = r.get("context", {}) if isinstance(r, dict) else {}
    reh = ctx.get("raw_event_hash", raw_event_hash)
    enh = ctx.get("enrichment_hash", raw_event_hash)
    ccmh = ctx.get("ccm_obs_hash", raw_event_hash)

    # Build leaf object used for Merkle leaf hashing
    leaf_obj = {"v": 1, "reh": reh, "enh": enh, "ccmh": ccmh}
    leaf = merkle.leaf_hash(jcs.canonicalize(leaf_obj))

    print("raw_event_hash matches:", reh == raw_event_hash)
    print("leaf matches:", leaf.hex() == r.get("leafHash"))

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: verify_receipt.py <receipt.json> <observation.json>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
