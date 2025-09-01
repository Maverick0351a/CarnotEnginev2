"""
HTTP Message Signatures verification (simplified), inspired by IETF draft.
- Uses two headers: `Signature-Input` and `Signature`.
- Supports Ed25519 with base64url signature, detached payload.
- Minimal covered components: "@method", "@target-uri", and explicit header names.

This is not a full implementation of the latest draft but is structured and
robust enough for testing. For production, replace with a vetted library.
"""
from __future__ import annotations
import base64
from dataclasses import dataclass
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

@dataclass
class SigParams:
    label: str
    covered: List[str]  # components
    created: int | None
    keyid: str


def _parse_sig_input(h: str) -> Dict[str, SigParams]:
    # Example:
    # Signature-Input: sig1=("@method" "@target-uri" "content-digest" "content-type");created=1618884473;keyid="kid-1"
    res: Dict[str, SigParams] = {}
    for part in h.split(','):
        part = part.strip()
        if not part:
            continue
        label, rest = part.split('=', 1)
        label = label.strip()
        if not rest.startswith('('):
            continue
        comps, rest2 = rest.split(')', 1)
        comps = comps[1:]
        covered = []
        for c in comps.split(' '):
            c = c.strip()
            if not c:
                continue
            if c[0] == c[-1] == '"':
                c = c[1:-1]
            covered.append(c)
        created = None
        keyid = ''
        for attr in rest2.split(';'):
            attr = attr.strip()
            if not attr:
                continue
            if attr.startswith('created='):
                try:
                    created = int(attr.split('=',1)[1])
                except Exception:
                    created = None
            if attr.startswith('keyid='):
                v = attr.split('=',1)[1]
                if v and v[0] == v[-1] == '"':
                    v = v[1:-1]
                keyid = v
        res[label] = SigParams(label, covered, created, keyid)
    return res


def _parse_signature(h: str) -> Dict[str, bytes]:
    # Example: Signature: sig1=:BASE64URL:,
    res: Dict[str, bytes] = {}
    for part in h.split(','):
        part = part.strip()
        if not part:
            continue
        label, rest = part.split('=',1)
        label = label.strip()
        if rest.startswith(':') and rest.endswith(':'):
            b64 = rest[1:-1]
            res[label] = base64.urlsafe_b64decode(b64 + '==')
    return res


def _build_sig_base(params: SigParams, headers: Dict[str,str], method: str, target_uri: str) -> bytes:
    lines: List[str] = []
    for c in params.covered:
        if c == '@method':
            lines.append(f"@method: {method.upper()}")
        elif c == '@target-uri':
            lines.append(f"@target-uri: {target_uri}")
        else:
            v = headers.get(c)
            if v is None:
                raise ValueError(f"missing covered component: {c}")
            lines.append(f"{c.lower()}: {v}")
    # Add the params line per draft
    params_items = [f'("' + '" "'.join(params.covered) + '")']
    if params.created is not None:
        params_items.append(f";created={params.created}")
    if params.keyid:
        params_items.append(f";keyid=\"{params.keyid}\"")
    lines.append(f"@signature-params: {''.join(params_items)}")
    return '\n'.join(lines).encode('utf-8')


def verify(headers: Dict[str,str], method: str = 'POST', target_uri: str = '/ingest', key_resolver=None) -> bool:
    sig_input = headers.get('signature-input') or headers.get('Signature-Input')
    sig_header = headers.get('signature') or headers.get('Signature')
    if not sig_input or not sig_header:
        return False
    inputs = _parse_sig_input(sig_input)
    sigs = _parse_signature(sig_header)
    if not inputs or not sigs:
        return False

    # Verify first one we can resolve
    for label, params in inputs.items():
        if label not in sigs:
            continue
        if not params.keyid or key_resolver is None:
            continue
        pub = key_resolver(params.keyid)
        if pub is None:
            continue
        base = _build_sig_base(params, {k.lower(): v for k,v in headers.items()}, method, target_uri)
        try:
            if isinstance(pub, Ed25519PublicKey):
                pub.verify(sigs[label], base)
                return True
        except Exception:
            continue
    return False
