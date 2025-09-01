from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jsonschema import validate
import datetime, hashlib, json
from signet.keyprovider import KeyProvider
from signet.transparency_log import TransparencyLog
from signet import receipts, jcs, merkle

app = FastAPI(title="CarnotEngine Signet API", version="v7.2")
KEYS = KeyProvider()
TL = TransparencyLog()

class IngestRequest(BaseModel):
    batch: list  # list of observation dicts; client ensures schema elsewhere

@app.post("/ingest")
async def ingest(req: IngestRequest):
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
