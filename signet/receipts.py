import base64, json, hashlib
from typing import List, Dict, Tuple
from . import jcs, merkle

def compute_leaf(raw_event_hash: str, enrichment_hash: str, ccm_obs_hash: str) -> bytes:
    leaf_obj = {
        "v": 1,
        "reh": raw_event_hash,
        "enh": enrichment_hash,
        "ccmh": ccm_obs_hash
    }
    return merkle.leaf_hash(jcs.canonicalize(leaf_obj))

def build_receipts(leaves: List[bytes], tree, key_provider, contexts: List[Dict] | None = None) -> Tuple[List[Dict], bytes, str, str]:
    root, tree_layers = merkle.build_tree(leaves)
    receipts = []
    for idx, _ in enumerate(leaves):
        proof = merkle.audit_proof(tree_layers, idx)
        kid, sig = key_provider.sign(root)
        payload = {
            "version": "1",
            "leafHash": leaves[idx].hex(),
            "proof": [p.hex() for p in proof],
            "signature": sig,
            "keyId": kid
        }
        if contexts and idx < len(contexts):
            ctx = contexts[idx]
            payload["context"] = {
                "raw_event_hash": ctx.get("raw_event_hash", ""),
                "enrichment_hash": ctx.get("enrichment_hash", ""),
                "ccm_obs_hash": ctx.get("ccm_obs_hash", ""),
            }
        receipts.append(payload)
    return receipts, root, kid, sig
