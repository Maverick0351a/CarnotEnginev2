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
KEYS = KeyProvider()
TL = TransparencyLog()

class IngestRequest(BaseModel):
    batch: list  # list of observation dicts; client ensures schema elsewhere

VERIFY_HTTP_SIG = bool(int(os.getenv('VERIFY_HTTP_SIG', '0')))

@app.post("/ingest")
async def ingest(req: IngestRequest, request: Request):
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
    leaves = []
    payloads = []
    for obs in req.batch:
        raw_hash = hashlib.sha256(jcs.canonicalize(obs)).hexdigest()
        # In a full pipeline, we would carry enrichment + CCM hashes. Scaffold uses raw twice.
        leaf = receipts.compute_leaf(raw_hash, raw_hash, raw_hash)
        leaves.append(leaf)
        payloads.append(jcs.canonicalize(obs))

    recs, root, kid, sig = receipts.build_receipts(leaves, None, KEYS)
    # persist leaves (payloads) in TL
    for leaf, pl in zip(leaves, payloads):
        TL.append(leaf, pl)
    # update STH
    TL.update_sth(tree_size=len(TL.leaves()), root_hash=root, signature=sig, key_id=kid)

    return JSONResponse({
        "receipts": recs,
        "sth": TL.get_sth()
    })

@app.get("/jwks.json")
async def jwks():
    return JSONResponse(KEYS.jwks())

@app.get("/sth")
async def sth():
    return JSONResponse(TL.get_sth())
