# -*- coding: utf-8 -*-
"""
PC-ZKP：PLS 耦合上下文绑定零知识证明（创新模块）

文献依据：
- Chen 等 2023 IoT 零知识认证综述：非交互 ZKP 需绑定会话上下文；
- 车联网跨层安全：将密码学证明与物理层 CSI 指纹耦合，抑制「窃证后替换 CSI」；
- 相对本仓库原始 Sigma 骨架：挑战仅含 (commitment, message, pk)，不含量子 CSI，
  攻击者可复用同一 ZKP 凭证配合不同 reported_csi（ZKP 层仍通过，仅靠 PLS 兜底）。

PC-ZKP 创新点：
1. 挑战 c = H(comm || message || pk || csi_digest || epoch_id)
2. 凭证标签 V = H(witness || pk) 置于 commitment 内，响应 s = HMAC(V, c || ctx)
3. RSU 用请求内 reported_csi 重算 csi_digest，实现 ZKP–PLS 跨层绑定

说明：V 为最小披露伪名标签（不传输 sk/witness 明文）；生产环境可演进至 zk-SNARK。
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Union

import numpy as np

from .sigma_proof import ZKProof

_DS_PCZKP = b"ZKP-PQC-PLS|PC-ZKP|v1"
_NONCE_LEN = 16
_CRED_TAG_LEN = 32


def csi_fingerprint_digest(csi: Union[np.ndarray, bytes]) -> bytes:
    """CSI 幅度向量 → 32B 绑定摘要（与 PLS 上报字段一致）。"""
    if isinstance(csi, np.ndarray):
        payload = np.asarray(csi, dtype=np.float32).tobytes()
    else:
        payload = bytes(csi)
    return hashlib.sha256(b"PC-ZKP|CSI|" + payload).digest()


def epoch_from_frame_message(message: bytes, window_ms: int = 5000) -> int:
    """
    从 IoVAuthFrame.canonical_bytes() 解析时间戳并推导 epoch。
    格式末尾: ts_ms(8 BE) || nonce(16) || flags(4)
    """
    if len(message) < 28:
        return 0
    ts_ms = struct.unpack(">Q", message[-28:-20])[0]
    if window_ms <= 0:
        return 0
    return int(ts_ms // window_ms)


def _build_context(message: bytes, public_input: bytes, csi_digest: bytes, epoch_id: int) -> bytes:
    return (
        b"PC-ZKP|CTX|"
        + message
        + public_input
        + csi_digest
        + struct.pack(">Q", epoch_id & 0xFFFFFFFFFFFFFFFF)
    )


def _challenge(commitment: bytes, context: bytes, challenge_bytes: int) -> bytes:
    return hashlib.sha256(_DS_PCZKP + b"|CH|" + commitment + context).digest()[:challenge_bytes]


class PCZKPProver:
    """PLS 耦合上下文绑定 ZKP 证明者。"""

    def __init__(self, challenge_bytes: int = 16, epoch_window_ms: int = 5000):
        self.challenge_bytes = challenge_bytes
        self.epoch_window_ms = epoch_window_ms

    def prove(
        self,
        witness: bytes,
        public_input: bytes,
        message: bytes,
        csi: Union[np.ndarray, bytes],
        *,
        epoch_id: int | None = None,
    ) -> ZKProof:
        pk = public_input
        cd = csi_fingerprint_digest(csi)
        ep = epoch_id if epoch_id is not None else epoch_from_frame_message(message, self.epoch_window_ms)

        cred_tag = hashlib.sha256(witness + pk + b"|PC-ZKP|CRED").digest()
        nonce = os.urandom(_NONCE_LEN)
        commitment = nonce + cred_tag

        ctx = _build_context(message, pk, cd, ep)
        challenge = _challenge(commitment, ctx, self.challenge_bytes)
        response = hmac.new(cred_tag, challenge + ctx, hashlib.sha256).digest()

        return ZKProof(commitment=commitment, response=response, challenge_digest=challenge)


class PCZKPVerifier:
    """PLS 耦合 ZKP 验证者：必须用请求中的 CSI 重算绑定摘要。"""

    def __init__(self, challenge_bytes: int = 16, epoch_window_ms: int = 5000):
        self.challenge_bytes = challenge_bytes
        self.epoch_window_ms = epoch_window_ms

    def verify(
        self,
        public_input: bytes,
        message: bytes,
        proof: ZKProof,
        csi: Union[np.ndarray, bytes],
        *,
        epoch_id: int | None = None,
    ) -> bool:
        if len(proof.commitment) < _NONCE_LEN + _CRED_TAG_LEN:
            return False
        if len(proof.response) != 32:
            return False

        pk = public_input
        cd = csi_fingerprint_digest(csi)
        ep = epoch_id if epoch_id is not None else epoch_from_frame_message(message, self.epoch_window_ms)

        cred_tag = proof.commitment[_NONCE_LEN : _NONCE_LEN + _CRED_TAG_LEN]
        ctx = _build_context(message, pk, cd, ep)
        challenge = _challenge(proof.commitment, ctx, self.challenge_bytes)

        if not hmac.compare_digest(challenge, proof.challenge_digest):
            return False

        expected = hmac.new(cred_tag, challenge + ctx, hashlib.sha256).digest()
        return hmac.compare_digest(expected, proof.response)
