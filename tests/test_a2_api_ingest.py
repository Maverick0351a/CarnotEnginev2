import base64
import hashlib
import json
import os
import time
import importlib
from starlette.testclient import TestClient


def build_content_digest(body: bytes, alg='sha-256') -> str:
    if alg == 'sha-256':
        h = hashlib.sha256(body).digest()
    elif alg == 'sha-512':
        h = hashlib.sha512(body).digest()
    else:
        raise ValueError('unsupported alg')
    return f"{alg}=:{base64.b64encode(h).decode('ascii').rstrip('=')}:"


def build_signature_headers(kp, covered, method, target_uri, extra_headers):
    created = int(time.time())
    label = 'sig1'
    covered_list = ' '.join(f'"{c}"' for c in covered)
    sig_input = f'{label}=({covered_list});created={created};keyid="{kp.current.key_id}"'

    # Build base per our verifier
    lines = []
    headers_l = {k.lower(): v for k, v in extra_headers.items()}
    for c in covered:
        if c == '@method':
            lines.append(f"@method: {method.upper()}")
        elif c == '@target-uri':
            lines.append(f"@target-uri: {target_uri}")
        else:
            lines.append(f"{c.lower()}: {headers_l[c.lower()]}")
    lines.append(f"@signature-params: (" + ' '.join(f'"{c}"' for c in covered) + f");created={created};keyid=\"{kp.current.key_id}\"")
    signing_base = '\n'.join(lines).encode('utf-8')
    kid, sig_b64u = kp.sign(signing_base)
    sig_header = f'{label}=:{sig_b64u}:'
    hdrs = {
        'signature-input': sig_input,
        'signature': sig_header,
    }
    hdrs.update(extra_headers)
    return hdrs


def setup_app_with_flag():
    os.environ['VERIFY_HTTP_SIG'] = '1'
    import api.main as m
    importlib.reload(m)
    return m


def test_ingest_signature_and_digest_ok():
    m = setup_app_with_flag()
    client = TestClient(m.app)
    body = {"batch": [{"ok": 1}]}
    body_bytes = json.dumps(body).encode('utf-8')
    cd = build_content_digest(body_bytes, 'sha-256')
    headers = build_signature_headers(
        m.KEYS,
        covered=['@method','@target-uri','content-type','content-digest'],
        method='POST', target_uri='/ingest',
        extra_headers={'content-type': 'application/json', 'content-digest': cd}
    )
    r = client.post('/ingest', headers=headers, json=body)
    assert r.status_code == 200, r.text


def test_ingest_header_tamper_fails():
    m = setup_app_with_flag()
    client = TestClient(m.app)
    body = {"batch": [{"ok": 1}]}
    body_bytes = json.dumps(body).encode('utf-8')
    cd = build_content_digest(body_bytes, 'sha-256')
    headers = build_signature_headers(
        m.KEYS,
        covered=['@method','@target-uri','content-type','content-digest'],
        method='POST', target_uri='/ingest',
        extra_headers={'content-type': 'application/json', 'content-digest': cd}
    )
    headers['content-type'] = 'text/plain'  # tamper covered header
    r = client.post('/ingest', headers=headers, json=body)
    assert r.status_code == 401


def test_ingest_body_tamper_fails():
    m = setup_app_with_flag()
    client = TestClient(m.app)
    good_body = {"batch": [{"ok": 1}]}
    bad_body = {"batch": [{"ok": 2}]}
    good_bytes = json.dumps(good_body).encode('utf-8')
    cd = build_content_digest(good_bytes, 'sha-256')
    headers = build_signature_headers(
        m.KEYS,
        covered=['@method','@target-uri','content-type','content-digest'],
        method='POST', target_uri='/ingest',
        extra_headers={'content-type': 'application/json', 'content-digest': cd}
    )
    # Send mismatched body
    r = client.post('/ingest', headers=headers, json=bad_body)
    assert r.status_code == 400


def test_ingest_wrong_kid_fails():
    m = setup_app_with_flag()
    client = TestClient(m.app)
    body = {"batch": [{"ok": 1}]}
    body_bytes = json.dumps(body).encode('utf-8')
    cd = build_content_digest(body_bytes, 'sha-256')
    # Use a different signer
    from signet.keyprovider import KeyProvider
    other = KeyProvider()
    headers = build_signature_headers(
        other,
        covered=['@method','@target-uri','content-type','content-digest'],
        method='POST', target_uri='/ingest',
        extra_headers={'content-type': 'application/json', 'content-digest': cd}
    )
    r = client.post('/ingest', headers=headers, json=body)
    assert r.status_code == 401
