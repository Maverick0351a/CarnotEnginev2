import base64
import os
import time
from signet.http_signatures import verify as verify_http_sig
from signet.keyprovider import KeyProvider


def make_headers(kp: KeyProvider, covered, method='POST', target_uri='/ingest', extra=None):
    if extra is None:
        extra = {}
    created = int(time.time())
    label = 'sig1'
    covered_list = ' '.join(f'"{c}"' for c in covered)
    sig_input = f'{label}=({covered_list});created={created};keyid="{kp.current.key_id}"'
    base_lines = []
    hdrs = {k.lower(): v for k,v in extra.items()}
    for c in covered:
        if c == '@method':
            base_lines.append(f"@method: {method}")
        elif c == '@target-uri':
            base_lines.append(f"@target-uri: {target_uri}")
        else:
            base_lines.append(f"{c.lower()}: {hdrs[c.lower()]}")
    base_lines.append(f"@signature-params: (" + ' '.join(f'"{c}"' for c in covered) + f");created={created};keyid=\"{kp.current.key_id}\"")
    signing_base = '\n'.join(base_lines).encode('utf-8')
    kid, sig = kp.sign(signing_base)
    sig_header = f'{label}:' + base64.urlsafe_b64encode(base64.urlsafe_b64decode(sig + '==')).decode('ascii').rstrip('=') + ':'
    headers = {
        'signature-input': sig_input,
        'signature': sig_header,
    }
    headers.update(extra)
    return headers


def test_http_signatures_positive():
    kp = KeyProvider()
    headers = make_headers(kp, covered=['@method','@target-uri','content-type'], extra={'content-type':'application/json'})
    ok = verify_http_sig(headers, method='POST', target_uri='/ingest', key_resolver=kp.get_pubkey)
    assert ok


def test_http_signatures_header_tamper_fails():
    kp = KeyProvider()
    headers = make_headers(kp, covered=['@method','@target-uri','content-type'], extra={'content-type':'application/json'})
    headers['content-type'] = 'text/plain'
    ok = verify_http_sig(headers, method='POST', target_uri='/ingest', key_resolver=kp.get_pubkey)
    assert not ok


def test_http_signatures_wrong_kid_fails():
    kp = KeyProvider()
    kp.rotate()  # change kid so resolver won't match
    other = KeyProvider()
    headers = make_headers(other, covered=['@method','@target-uri'], extra={})
    ok = verify_http_sig(headers, method='POST', target_uri='/ingest', key_resolver=kp.get_pubkey)
    assert not ok
