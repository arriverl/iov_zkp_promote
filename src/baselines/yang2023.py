# -*- coding: utf-8 -*-
"""
Yang et al. (2023) IoV 认证与密钥协商 — 密码学原语复现。

文献: Q. Yang, X. Zhu, X. Wang, J. Fu, J. Zheng, Y. Liu,
「A novel authentication and key agreement scheme for Internet of Vehicles」,
Future Generation Computer Systems, 145:415–428, 2023.
DOI: 10.1016/j.future.2023.04.004

实现说明:
  复现论文「初始认证与密钥协商阶段」的核心运算（ECC 点乘/ECDH、SHA-256、XOR 假名/路线掩码），
  使用 cryptography 库 secp256r1 在本机实测 RSU 验签延迟与报文体积。
  非 NS-3 网络仿真；与融合方案一样为 Python 原型级密码学 benchmark。
"""
from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    n = max(len(a), len(b))
    a = a.ljust(n, b"\x00")
    b = b.ljust(n, b"\x00")
    return bytes(x ^ y for x, y in zip(a, b))


def _pk_bytes(pk: ec.EllipticCurvePublicKey) -> bytes:
    return pk.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


@dataclass
class YangAuthRequest:
    """车辆 → RSU 认证报文（对应论文 Table 1 认证阶段外发字段）。"""

    Ti: bytes
    Ri_pub: bytes
    rid_masked: bytes
    route_masked: bytes
    auth_token: bytes
    vehicle_pk: bytes

    @property
    def comm_bytes(self) -> int:
        return (
            len(self.Ti)
            + len(self.Ri_pub)
            + len(self.rid_masked)
            + len(self.route_masked)
            + len(self.auth_token)
            + len(self.vehicle_pk)
        )


class Yang2023IoVAuth:
    """
    三方模型 TA / Vehicle / RSU；benchmark 仅计时单次 OBU→RSU 认证轮次。
    XOR 假名与路线掩码保留论文弱点（短哈希掩码长路线），用于能力维对照。
    """

    def __init__(self) -> None:
        self._curve = ec.SECP256R1()
        self.vehicle_sk = ec.generate_private_key(self._curve)
        self.vehicle_pk = self.vehicle_sk.public_key()
        self.rsu_sk = ec.generate_private_key(self._curve)
        self.rsu_pk = self.rsu_sk.public_key()
        # 注册阶段假名分量 PID_{i,1}, PID_{i,2}（TA 可追溯 RID_i = h(S·PID1) ⊕ PID2）
        self.pid1 = os.urandom(32)
        self.pid2 = os.urandom(32)
        self._session_counter = 0

    def vehicle_build_request(self, route_info: bytes, rsu_id: bytes) -> Tuple[YangAuthRequest, bytes]:
        """OBU 侧：生成 ephemeral 标量、掩码假名/路线、认证令牌。"""
        self._session_counter += 1
        ri = ec.generate_private_key(self._curve)
        alpha = ec.generate_private_key(self._curve)

        Ti = _pk_bytes(ri.public_key())
        Ri_pub = _pk_bytes(alpha.public_key())

        # X_i = α_i · PK_RSU（ECDH 共享秘密）
        x_i = alpha.exchange(ec.ECDH(), self.rsu_pk)
        h_xi = _sha256(x_i)

        # 路线掩码: m ⊕ h(α_i)（论文采用 XOR；已知对长路线存在泄露风险）
        route_padded = route_info.ljust(64, b"\x00")[:64]
        route_masked = _xor_bytes(route_padded, h_xi)

        # 假名掩码 RID 相关字段
        rid_inner = _sha256(self.pid1, _pk_bytes(self.vehicle_pk))
        rid_masked = _xor_bytes(rid_inner, self.pid2)

        auth_token = _sha256(Ti, Ri_pub, rid_masked, route_masked, rsu_id, str(self._session_counter).encode())

        req = YangAuthRequest(
            Ti=Ti,
            Ri_pub=Ri_pub,
            rid_masked=rid_masked,
            route_masked=route_masked,
            auth_token=auth_token,
            vehicle_pk=_pk_bytes(self.vehicle_pk),
        )
        # 会话密钥（双方均可导出，RSU 验证时重算）
        sk = _sha256(x_i, auth_token)
        return req, sk

    def rsu_verify(self, req: YangAuthRequest, rsu_id: bytes, session_id: str) -> Tuple[bool, bytes]:
        """RSU 侧：ECDH 恢复共享秘密、校验 auth_token、导出会话密钥。"""
        peer_pk = ec.EllipticCurvePublicKey.from_encoded_point(self._curve, req.Ri_pub)
        x_j = self.rsu_sk.exchange(ec.ECDH(), peer_pk)

        expected_token = _sha256(req.Ti, req.Ri_pub, req.rid_masked, req.route_masked, rsu_id, session_id.encode())
        if expected_token != req.auth_token:
            return False, b""

        sk = _sha256(x_j, req.auth_token)
        return True, sk


def benchmark_yang2023_round(proto: Yang2023IoVAuth, route: bytes, rsu_id: bytes) -> Tuple[float, float, int]:
    """返回 (rsu_verify_ms, e2e_ms, comm_bytes)。"""
    t0 = time.perf_counter()
    req, _ = proto.vehicle_build_request(route, rsu_id)
    sid = str(proto._session_counter)
    t_rsu = time.perf_counter()
    ok, _ = proto.rsu_verify(req, rsu_id, sid)
    rsu_ms = (time.perf_counter() - t_rsu) * 1000
    e2e_ms = (time.perf_counter() - t0) * 1000
    if not ok:
        raise RuntimeError("Yang2023: RSU verify failed")
    return rsu_ms, e2e_ms, req.comm_bytes
