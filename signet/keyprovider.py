import base64, json, os, time
from dataclasses import dataclass
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

@dataclass
class KeyRecord:
    key_id: str
    priv: Ed25519PrivateKey
    created: float

class KeyProvider:
    def __init__(self, rotation_interval_seconds: int = 3600):
        """Initialize provider.

        rotation_interval_seconds: desired minimum lifetime for a key before
        automatic rotation. Rotation history is kept in-memory.
        """
        self.rotation_interval = rotation_interval_seconds
        self.current = self._new_key()
        self.history: List[KeyRecord] = [self.current]

    def _new_key(self) -> KeyRecord:
        priv = Ed25519PrivateKey.generate()
        kid = base64.urlsafe_b64encode(os.urandom(8)).decode('ascii').rstrip('=')
        return KeyRecord(kid, priv, time.time())

    def rotate(self) -> KeyRecord:
        kr = self._new_key()
        self.current = kr
        self.history.append(kr)
        return kr

    def maybe_rotate(self):
        """Rotate key if rotation interval elapsed."""
        if time.time() - self.current.created >= self.rotation_interval:
            self.rotate()

    def list_keys(self) -> List[KeyRecord]:
        return list(self.history)

    def sign(self, msg: bytes) -> (str, str):
        sig = self.current.priv.sign(msg)
        return self.current.key_id, base64.urlsafe_b64encode(sig).decode('ascii').rstrip('=')

    def get_pubkey(self, kid: str):
        """Return Ed25519 public key object for given key id or None.

        Searches current then history.
        """
        if kid == self.current.key_id:
            return self.current.priv.public_key()
        for kr in self.history:
            if kid == kr.key_id:
                return kr.priv.public_key()
        return None

    def jwks(self) -> Dict:
        keys_json = []
        for kr in self.history[-5:][::-1]:  # expose last up to 5 keys (current first)
            pub = kr.priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            keys_json.append({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kr.key_id,
                "x": base64.urlsafe_b64encode(pub).decode('ascii').rstrip('=')
            })
        return {"keys": keys_json}
