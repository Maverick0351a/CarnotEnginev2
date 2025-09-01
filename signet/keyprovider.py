import base64, json, os, time
from dataclasses import dataclass
from typing import Dict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

@dataclass
class KeyRecord:
    key_id: str
    priv: Ed25519PrivateKey
    created: float

class KeyProvider:
    def __init__(self):
        self.current = self._new_key()

    def _new_key(self) -> KeyRecord:
        priv = Ed25519PrivateKey.generate()
        kid = base64.urlsafe_b64encode(os.urandom(8)).decode('ascii').rstrip('=')
        return KeyRecord(kid, priv, time.time())

    def rotate(self) -> KeyRecord:
        self.current = self._new_key()
        return self.current

    def sign(self, msg: bytes) -> (str, str):
        sig = self.current.priv.sign(msg)
        return self.current.key_id, base64.urlsafe_b64encode(sig).decode('ascii').rstrip('=')

    def get_pubkey(self, kid: str):
        """Return Ed25519 public key object for given key id or None."""
        if kid == self.current.key_id:
            return self.current.priv.public_key()
        return None

    def jwks(self) -> Dict:
        pub = self.current.priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return {
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": self.current.key_id,
                "x": base64.urlsafe_b64encode(pub).decode('ascii').rstrip('=')
            }]
        }
