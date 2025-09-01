from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jsonschema import validate
import os, datetime, hashlib, json
from signet.keyprovider import KeyProvider
from signet.transparency_log import TransparencyLog
from signet import receipts, jcs, merkle
import base64, re

app = FastAPI(title="CarnotEngine Signet API", version="v7.2")
KEYS = KeyProvider(rotation_interval_seconds=int(os.getenv('SIGNET_KEY_ROTATE_SECS', '3600')))
TL = TransparencyLog()

class IngestRequest(BaseModel):
    batch: list  # retained for potential future explicit validation; not used directly in handler

VERIFY_HTTP_SIG = bool(int(os.getenv('VERIFY_HTTP_SIG', '0')))

@app.post("/ingest")
async def ingest(request: Request):
    # Auto-rotate if needed before processing new batch
    KEYS.maybe_rotate()
    # Verify HTTP Message Signature if enabled
    if VERIFY_HTTP_SIG:
        body_bytes = await request.body()
        # Enforce Content-Digest if provided (e.g., "sha-256=:BASE64:")
        cd = request.headers.get('content-digest') or request.headers.get('Content-Digest')
        if cd:
            # Support single-value digests; parse algo=value pairs separated by comma
            # Format per draft (RFC 9530): algo=:base64:
            def parse_cd(val: str):
                parts = [p.strip() for p in val.split(',') if p.strip()]
                out = {}
                for p in parts:
                    if ':' in p:
                        alg, rest = p.split(':', 1)
                        alg = alg.strip().lower()
                        if rest.endswith(':'):
                            b64 = rest.strip(':')
                        else:
                            # could be algo=... format; fallback
                            b64 = rest.strip()
                        out[alg] = b64
                return out
            cds = parse_cd(cd)
            import hashlib, base64 as b64
            if 'sha-256' in cds:
                exp = b64.b64encode(hashlib.sha256(body_bytes).digest()).decode('ascii').rstrip('=')
                got = cds['sha-256'].rstrip('=')
                if exp != got:
                    raise HTTPException(status_code=400, detail="content-digest mismatch")
            elif 'sha-512' in cds:
                exp = b64.b64encode(hashlib.sha512(body_bytes).digest()).decode('ascii').rstrip('=')
                got = cds['sha-512'].rstrip('=')
                if exp != got:
                    raise HTTPException(status_code=400, detail="content-digest mismatch")
        from signet.http_signatures import verify as verify_http_sig
        def resolver(kid: str):
            pk = KEYS.get_pubkey(kid)
            return pk
        # Build lower-cased headers dict
        hdrs = {k.lower(): v for k, v in request.headers.items()}
        if not verify_http_sig(hdrs, method=request.method, target_uri=str(request.url.path), key_resolver=resolver):
            raise HTTPException(status_code=401, detail="invalid http message signature")
    # Manually parse JSON to control error codes (avoid FastAPI 422 before signature check)
    try:
        body_obj = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json body")
    if not isinstance(body_obj, dict) or 'batch' not in body_obj or not isinstance(body_obj['batch'], list):
        raise HTTPException(status_code=400, detail="invalid batch format")
    leaves = []
    payloads = []
    contexts = []
    for obs in body_obj['batch']:
        can = jcs.canonicalize(obs)
        raw_hash = hashlib.sha256(can).hexdigest()
        # Placeholder enrichment/ccm conversions can be modelled as identity for now
        enrichment_hash = raw_hash
        ccm_obs_hash = raw_hash
        leaf = receipts.compute_leaf(raw_hash, enrichment_hash, ccm_obs_hash)
        leaves.append(leaf)
        payloads.append(can)
        contexts.append({
            "raw_event_hash": raw_hash,
            "enrichment_hash": enrichment_hash,
            "ccm_obs_hash": ccm_obs_hash,
        })

    recs, root, kid, sig = receipts.build_receipts(leaves, None, KEYS, contexts)
    # persist leaves (payloads) in TL
    for leaf, pl in zip(leaves, payloads):
        TL.append(leaf, pl)
    # update STH
    TL.update_sth(tree_size=len(TL.leaves()), root_hash=root, signature=sig, key_id=kid)

    return JSONResponse({"receipts": recs, "sth": TL.get_sth()})

@app.get("/jwks.json")
async def jwks():
    return JSONResponse(KEYS.jwks())

@app.get("/sth")
async def sth():
    return JSONResponse(TL.get_sth())

@app.post("/rotate-key")
async def rotate_key():
    kr = KEYS.rotate()
    return {"rotated": True, "kid": kr.key_id, "created": kr.created}
