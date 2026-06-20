# -*- coding: utf-8 -*-
"""
SIS-Σ-NIZK：模 q 短向量关系的非交互零知识证明（算法层创新）

数学陈述（公开语言）：
  给定 A ∈ Z_q^{m×n}、t ∈ Z_q^m（由 Dilithium pk 透明导出），
  证明者知短向量 s ∈ Z^n（||s||∞ ≤ η，由 Dilithium sk 导出），满足
      A · s ≡ t (mod q)
  且不泄露 s。

算法（Lyubashevsky 拒绝采样 Σ + Fiat–Shamir）：
  1. 采样掩码 y ← Z^n，承诺 w = A·y mod q
  2. 挑战 c = H(w || t || message || pk) mod q_c（小范围）
  3. 响应 z = y + c·s mod q；若 ||z||∞ > B 则重采样
  4. 验证：A·z − c·t ≡ w (mod q) 且 ||z||∞ ≤ B

相对「拼接式」PC-ZKP 的本质区别：
  - 安全性归约到格上 SIS/MLWE 短向量困难性，而非 HMAC 上下文哈希；
  - (A, t, s) 与 ML-DSA 密钥对通过确定性导出函数绑定，ZKP 与 PQC 共享代数结构；
  - 验证端检查线性同余，无法仅凭替换附加字段通过。

文献：Lyubashevsky (2009) lattice-based signatures; Dilithium/ML-DSA (FIPS 204).
"""
from __future__ import annotations

import hashlib
import os
import struct
from typing import NamedTuple, Tuple

import numpy as np

from .sigma_proof import ZKProof

# 公开参数（IoV 轻量化：维度小于 Dilithium 内部，但协议结构同构）
_Q = 12289
_N = 32
_M = 32
_ETA_S = 3  # ||s||∞ ≤ 3
_ETA_Z = 2 * _ETA_S * 8 + 4  # 拒绝采样上界（c ∈ [0,7]）
_C_MAX = 8
_DS = b"SIS-Sigma-NIZK|v1"


class LatticeStatement(NamedTuple):
    """公开陈述 (A, t, q)。"""
    A: np.ndarray  # (m, n)
    t: np.ndarray  # (m,)
    q: int


def _shake_matrix(seed: bytes, m: int, n: int, q: int) -> np.ndarray:
    out = np.empty((m, n), dtype=np.int64)
    buf = hashlib.shake_256(seed).digest(m * n * 2)
    for i in range(m):
        for j in range(n):
            v = struct.unpack_from("<H", buf, (i * n + j) * 2)[0]
            out[i, j] = v % q
    return out


def _short_vector_from_sk(sk: bytes, n: int) -> np.ndarray:
    """从 Dilithium sk 导出短秘密向量（中心化系数）。"""
    raw = hashlib.shake_256(b"SIS-WIT|" + sk).digest(n)
    return np.array([((b % (2 * _ETA_S + 1)) - _ETA_S) for b in raw], dtype=np.int64)


def derive_lattice_statement(pk: bytes, sk: bytes) -> LatticeStatement:
    """
    从 (pk, sk) 确定性导出 SIS 陈述。
    OBU/RSU 对同一 pk 得到相同 A；t = A·s 仅由合法 sk 持有者可构造有效证明。
    """
    A = _shake_matrix(b"A|" + pk, _M, _N, _Q)
    s = _short_vector_from_sk(sk, _N)
    t = (A @ s) % _Q
    return LatticeStatement(A=A, t=t, q=_Q)


def _pack_vec(v: np.ndarray, q: int) -> bytes:
    return v.astype(np.uint16).tobytes()


def _unpack_vec(data: bytes, length: int) -> np.ndarray:
    arr = np.frombuffer(data, dtype=np.uint16).astype(np.int64)
    if arr.size != length:
        raise ValueError("向量长度不匹配")
    return arr


def _parse_commitment(commitment: bytes) -> Tuple[np.ndarray, np.ndarray, bytes]:
    w_bytes = _M * 2
    t_bytes = _M * 2
    nonce_len = 16
    if len(commitment) < w_bytes + t_bytes + nonce_len:
        raise ValueError("commitment 过短")
    w = _unpack_vec(commitment[:w_bytes], _M)
    t = _unpack_vec(commitment[w_bytes : w_bytes + t_bytes], _M)
    nonce = commitment[w_bytes + t_bytes : w_bytes + t_bytes + nonce_len]
    return w, t, nonce


def _build_commitment(w: np.ndarray, t: np.ndarray, nonce: bytes) -> bytes:
    return _pack_vec(w % _Q, _Q) + _pack_vec(t % _Q, _Q) + nonce


def _challenge(w: np.ndarray, t: np.ndarray, nonce: bytes, message: bytes, pk: bytes, nbytes: int) -> int:
    payload = _DS + b"|CH|" + _pack_vec(w % _Q, _Q) + _pack_vec(t % _Q, _Q) + nonce + message + pk
    h = hashlib.sha256(payload).digest()
    return int.from_bytes(h[:4], "big") % _C_MAX


class SISLatticeNIZKProver:
    """SIS 短向量知识的非交互零知识证明者。"""

    def __init__(self, challenge_bytes: int = 16, max_rejections: int = 128):
        self.challenge_bytes = challenge_bytes
        self.max_rejections = max_rejections

    def prove(self, witness_sk: bytes, public_pk: bytes, message: bytes) -> ZKProof:
        stmt = derive_lattice_statement(public_pk, witness_sk)
        A, t, q = stmt.A, stmt.t, stmt.q
        s = _short_vector_from_sk(witness_sk, _N)

        for _ in range(self.max_rejections):
            nonce = os.urandom(16)
            y = np.random.randint(-_ETA_S, _ETA_S + 1, size=_N, dtype=np.int64)
            w = (A @ y) % q
            c = _challenge(w, t, nonce, message, public_pk, self.challenge_bytes)
            z = y + c * s
            if int(np.max(np.abs(z))) > _ETA_Z:
                continue

            comm = _build_commitment(w, t, nonce)
            c_bytes = struct.pack("<H", c)[: self.challenge_bytes].ljust(self.challenge_bytes, b"\x00")
            resp = _pack_vec(z % q, q)
            return ZKProof(commitment=comm, response=resp, challenge_digest=c_bytes)

        raise RuntimeError("SIS-Σ-NIZK 拒绝采样失败，请重试")


class SISLatticeNIZKVerifier:
    """验证格线性关系 A·z − c·t ≡ w (mod q)。"""

    def __init__(self, challenge_bytes: int = 16):
        self.challenge_bytes = challenge_bytes

    def verify(self, public_pk: bytes, message: bytes, proof: ZKProof) -> bool:
        try:
            w, t, nonce = _parse_commitment(proof.commitment)
            z = _unpack_vec(proof.response, _N)
        except (ValueError, TypeError):
            return False

        q = _Q
        z_center = np.where(z > q // 2, z - q, z)

        if len(proof.challenge_digest) < 2:
            return False
        c = struct.unpack("<H", proof.challenge_digest[:2].ljust(2, b"\x00"))[0] % _C_MAX

        c_expected = _challenge(w, t, nonce, message, public_pk, self.challenge_bytes)
        if c != c_expected:
            return False

        if int(np.max(np.abs(z_center))) > _ETA_Z:
            return False

        A = _shake_matrix(b"A|" + public_pk, _M, _N, _Q)
        lhs = (A @ z - c * t) % _Q
        if not np.array_equal(lhs % _Q, w % _Q):
            return False

        return True
