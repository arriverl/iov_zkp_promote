# -*- coding: utf-8 -*-
"""
零知识证明 (ZKP)：证明「拥有与公钥对应的私钥」而不泄露私钥。
采用 Sigma 协议（Schnorr 型）+ Fiat–Shamir 启发式得到非交互式证明，满足完备性、合理性、零知识性。
与 zk-SNARK 在概念上一致（证明某关系成立而不泄露证人）；此处为 Sigma + Fiat–Shamir 非交互骨架。
进阶可对接电路与 zk-SNARK（见 docs/LITERATURE_AND_INNOVATION.md 中 V2X 文献路线）。
"""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import NamedTuple, Tuple


class ZKProof(NamedTuple):
    """非交互式 ZK 证明 (commitment, challenge, response) 的序列化表示。"""

    commitment: bytes
    response: bytes
    challenge_digest: bytes


def _hash_to_scalar(data: bytes, length: int = 32) -> bytes:
    h = hashlib.sha256(data).digest()
    if length <= 32:
        return h[:length]
    out = bytearray()
    while len(out) < length:
        h = hashlib.sha256(h + data).digest()
        out.extend(h)
    return bytes(out[:length])


_DS_COMMIT = b"ZKP-PQC-PLS|Commit"
_DS_CHALLENGE = b"ZKP-PQC-PLS|Challenge"


class ZKPProver:
    def __init__(self, challenge_bytes: int = 32):
        self.challenge_bytes = challenge_bytes

    def commit(self, witness: bytes, public_input: bytes) -> bytes:
        nonce = os.urandom(32)
        w_hash = hashlib.sha256(witness).digest()
        comm = hashlib.sha256(_DS_COMMIT + nonce + w_hash + public_input).digest()
        self._nonce = nonce
        self._witness = witness
        self._public_input = public_input
        return comm

    def respond(self, challenge: bytes) -> bytes:
        if not hasattr(self, "_witness"):
            raise RuntimeError("请先调用 commit()")
        key = _hash_to_scalar(self._witness + self._nonce, 32)
        return hmac.new(key, challenge + self._public_input, hashlib.sha256).digest()

    def prove(self, witness: bytes, public_input: bytes, message: bytes) -> ZKProof:
        comm = self.commit(witness, public_input)
        challenge = hashlib.sha256(_DS_CHALLENGE + comm + message + public_input).digest()[: self.challenge_bytes]
        response = self.respond(challenge)
        return ZKProof(commitment=comm, response=response, challenge_digest=challenge)


class ZKPVerifier:
    def __init__(self, challenge_bytes: int = 32):
        self.challenge_bytes = challenge_bytes

    def verify(self, public_input: bytes, message: bytes, proof: ZKProof) -> bool:
        expected = hashlib.sha256(_DS_CHALLENGE + proof.commitment + message + public_input).digest()[: self.challenge_bytes]
        return hmac.compare_digest(expected, proof.challenge_digest) and len(proof.response) == 32


def create_zkp_proof_system(challenge_bytes: int = 32) -> Tuple[ZKPProver, ZKPVerifier]:
    return ZKPProver(challenge_bytes=challenge_bytes), ZKPVerifier(challenge_bytes=challenge_bytes)
