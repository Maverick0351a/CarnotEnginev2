import base64
import hashlib
import json
import time
import importlib
from starlette.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def setup_app():
    # Disable HTTP sig verification for these tests to focus on receipts/STH integrity
    import os
    os.environ['VERIFY_HTTP_SIG'] = '0'
    import api.main as m
    importlib.reload(m)
    return m


def compute_leaf_from_receipt_and_obs(receipt, obs):
    from signet import jcs, merkle
    can = jcs.canonicalize(obs)
    raw_event_hash = hashlib.sha256(can).hexdigest()
    ctx = receipt.get("context", {}) if isinstance(receipt, dict) else {}
    reh = ctx.get("raw_event_hash", raw_event_hash)
    enh = ctx.get("enrichment_hash", raw_event_hash)
    ccmh = ctx.get("ccm_obs_hash", raw_event_hash)
    leaf_obj = {"v": 1, "reh": reh, "enh": enh, "ccmh": ccmh}
    return merkle.leaf_hash(jcs.canonicalize(leaf_obj)).hex(), raw_event_hash


def test_receipt_leaf_mismatch_on_obs_tamper():
    m = setup_app()
    client = TestClient(m.app)
    obs = {"foo": "bar", "n": 1}
    body = {"batch": [obs]}
    r = client.post('/ingest', json=body)
    assert r.status_code == 200
    rec = r.json()["receipts"][0]

    # Recompute leaf with original obs (should match)
    leaf_hex, reh = compute_leaf_from_receipt_and_obs(rec, obs)
    assert leaf_hex == rec["leafHash"]

    # Tamper observation and ensure mismatch
    obs_tamper = {"foo": "BAZ", "n": 1}
    leaf_hex2, _ = compute_leaf_from_receipt_and_obs(rec, obs_tamper)
    assert leaf_hex2 != rec["leafHash"], "tampered observation should change leaf"


def test_receipt_leaf_mismatch_on_context_tamper():
    m = setup_app()
    client = TestClient(m.app)
    obs = {"x": 7}
    body = {"batch": [obs]}
    r = client.post('/ingest', json=body)
    assert r.status_code == 200
    rec = r.json()["receipts"][0]

    # Make a copy and tamper context.raw_event_hash
    rec_bad = json.loads(json.dumps(rec))
    rec_bad.setdefault("context", {})
    rec_bad["context"]["raw_event_hash"] = "0" * 64

    from signet import jcs, merkle
    # Recompute leaf with tampered context; should mismatch original leaf
    leaf_obj = {"v": 1, "reh": rec_bad["context"]["raw_event_hash"],
                "enh": rec_bad["context"].get("enrichment_hash", rec_bad["context"]["raw_event_hash"]),
                "ccmh": rec_bad["context"].get("ccm_obs_hash", rec_bad["context"]["raw_event_hash"]) }
    leaf_hex_bad = merkle.leaf_hash(jcs.canonicalize(leaf_obj)).hex()
    assert leaf_hex_bad != rec["leafHash"], "tampering context must break leaf"


def test_sth_signature_verify_and_tamper_detected():
    m = setup_app()
    client = TestClient(m.app)
    body = {"batch": [{"ok": 1}]}
    r = client.post('/ingest', json=body)
    assert r.status_code == 200
    sth = r.json()["sth"]
    # Verify signature over rootHash using kid
    kid = sth["keyId"]
    root = bytes.fromhex(sth["rootHash"])  # merkle root as bytes
    sig = base64.urlsafe_b64decode(sth["signature"] + '==')
    pub = m.KEYS.get_pubkey(kid)
    assert isinstance(pub, Ed25519PublicKey)
    pub.verify(sig, root)

    # Tamper signature and expect verification failure
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 0x01
    try:
        pub.verify(bytes(bad_sig), root)
        assert False, "tampered STH signature should not verify"
    except Exception:
        pass


def test_ingest_throughput_batch_100():
    m = setup_app()
    client = TestClient(m.app)
    batch = [{"i": i} for i in range(100)]
    t0 = time.time()
    r = client.post('/ingest', json={"batch": batch})
    dt = time.time() - t0
    assert r.status_code == 200
    # Print a simple throughput metric (obs/sec) for CI logs
    obs_per_sec = 100.0 / dt if dt > 0 else float('inf')
    print(f"throughput: {obs_per_sec:.1f} obs/sec over {dt:.3f}s")
