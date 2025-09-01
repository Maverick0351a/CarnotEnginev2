import hashlib
from typing import List

def h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def leaf_hash(data: bytes) -> bytes:
    return h(b'0' + data)

def node_hash(l: bytes, r: bytes) -> bytes:
    return h(b'1' + l + r)

def build_tree(leaves: List[bytes]) -> (bytes, List[List[bytes]]):
    if not leaves:
        return h(b''), []
    layer = [leaf_hash(x) for x in leaves]
    tree = [layer]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            if i+1 < len(layer):
                nxt.append(node_hash(layer[i], layer[i+1]))
            else:
                nxt.append(layer[i])
        tree.append(nxt)
        layer = nxt
    return layer[0], tree

def audit_proof(tree: List[List[bytes]], idx: int) -> List[bytes]:
    proof = []
    pos = idx
    for layer in tree[:-1]:
        sib = pos ^ 1
        if sib < len(layer):
            proof.append(layer[sib])
        pos >>= 1
    return proof
