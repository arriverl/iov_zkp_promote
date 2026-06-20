# -*- coding: utf-8 -*-
"""
ECDH + AES-GCM 假名改进基线 — 密码学原语复现。

对应汇报中的「改进方案」：以 ECDH 协商会话密钥，AES-GCM 加密假名凭证，
替代 Yang 2023 的 XOR 弱掩码；仍无 PQC / ZKP / PLS。

实现: cryptography 库 secp256r1 + HKDF-SHA256 + AES-256-GCM。
本机实测 RSU 验签延迟与报文体积（非 NS-3）。
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _pk_bytes(pk: ec.EllipticCurvePublicKey) -> bytes:
    return pk.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def _derive_aes_key(shared_secret: bytes, context: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"IoV-Pseudonym-AES|" + context,
    ).derive(shared_secret)


@dataclass
class EcdhAesAuthRequest:
    """车辆 → RSU：ephemeral 公钥 + 加密假名 + GCM nonce/tag 封装在 ciphertext 内。"""

    ephemeral_pk: bytes
    ciphertext: bytes
    epoch: int
    mac_context: bytes

    @property
    def comm_bytes(self) -> int:
        return len(self.ephemeral_pk) + len(self.ciphertext) + 8 + len(self.mac_context)


class EcdhAesPseudonymAuth:
    """假名 = H(vehicle_id || epoch)；线路上仅传输 AES-GCM 密文。"""

    def __init__(self) -> None:
        self._curve = ec.SECP256R1()
        self.vehicle_id = os.urandom(16)
        self.vehicle_sk = ec.generate_private_key(self._curve)
        self.vehicle_pk = self.vehicle_sk.public_key()
        self.rsu_sk = ec.generate_private_key(self._curve)
        self.rsu_pk = self.rsu_sk.public_key()
        self._epoch = 0

    def _pseudonym(self, epoch: int) -> bytes:
        return hashlib.sha256(self.vehicle_id + epoch.to_bytes(8, "big")).digest()

    def vehicle_build_request(self, rsu_id: bytes) -> EcdhAesAuthRequest:
        self._epoch += 1
        epoch = self._epoch
        eph_sk = ec.generate_private_key(self._curve)
        shared = eph_sk.exchange(ec.ECDH(), self.rsu_pk)
        aes_key = _derive_aes_key(shared, rsu_id)
        pseudonym = self._pseudonym(epoch)
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        ciphertext = nonce + aesgcm.encrypt(nonce, pseudonym, rsu_id + epoch.to_bytes(8, "big"))
        mac_context = hashlib.sha256(_pk_bytes(self.vehicle_pk) + rsu_id).digest()[:16]
        return EcdhAesAuthRequest(
            ephemeral_pk=_pk_bytes(eph_sk.public_key()),
            ciphertext=ciphertext,
            epoch=epoch,
            mac_context=mac_context,
        )

    def rsu_verify(self, req: EcdhAesAuthRequest, rsu_id: bytes) -> Tuple[bool, bytes]:
        peer_pk = ec.EllipticCurvePublicKey.from_encoded_point(self._curve, req.ephemeral_pk)
        shared = self.rsu_sk.exchange(ec.ECDH(), peer_pk)
        aes_key = _derive_aes_key(shared, rsu_id)
        nonce = req.ciphertext[:12]
        ct = req.ciphertext[12:]
        aesgcm = AESGCM(aes_key)
        aad = rsu_id + req.epoch.to_bytes(8, "big")
        try:
            pseudonym = aesgcm.decrypt(nonce, ct, aad)
        except Exception:
            return False, b""
        expected_ctx = hashlib.sha256(_pk_bytes(self.vehicle_pk) + rsu_id).digest()[:16]
        if req.mac_context != expected_ctx:
            return False, b""
        session_key = hashlib.sha256(shared + pseudonym).digest()
        return True, session_key


def benchmark_ecdh_aes_round(proto: EcdhAesPseudonymAuth, rsu_id: bytes) -> Tuple[float, float, int]:
    """返回 (rsu_verify_ms, e2e_ms, comm_bytes)。"""
    t0 = time.perf_counter()
    req = proto.vehicle_build_request(rsu_id)
    t_rsu = time.perf_counter()
    ok, _ = proto.rsu_verify(req, rsu_id)
    rsu_ms = (time.perf_counter() - t_rsu) * 1000
    e2e_ms = (time.perf_counter() - t0) * 1000
    if not ok:
        raise RuntimeError("ECDH+AES: RSU verify failed")
    return rsu_ms, e2e_ms, req.comm_bytes
