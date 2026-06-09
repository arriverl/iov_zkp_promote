# -*- coding: utf-8 -*-
"""
IoV / V2X 风格认证会话帧：将 RSU 挑战、时间窗与 nonce 绑定到签名与 ZKP 的公共输入上，
降低重放风险，并与近年文献中“上下文绑定 / 策略版本”的表述一致。
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class IoVAuthFrame:
    """
    单次认证会话的规范化载荷（证明者/验证者双方用同一规则序列化）。

    policy_flags（位图，可扩展）：
      bit0 — 要求 PQC 签名
      bit1 — 要求 ZKP
      bit2 — 要求 PLS
    """

    protocol_version: bytes = b"ZKP-PQC-PLS/1"
    rsu_id: bytes = b"RSU-DEFAULT"
    timestamp_unix_ms: int = 0
    nonce: bytes = b"\x00" * 16
    policy_flags: int = 0b111  # PQC | ZKP | PLS

    def __post_init__(self) -> None:
        if len(self.nonce) != 16:
            raise ValueError("nonce 必须为 16 字节")
        if not self.rsu_id:
            raise ValueError("rsu_id 不能为空")

    @staticmethod
    def fresh(rsu_id: bytes, nonce: Optional[bytes] = None) -> "IoVAuthFrame":
        """生成带当前时间与随机 nonce 的帧。"""
        import os

        n = nonce if nonce is not None else os.urandom(16)
        return IoVAuthFrame(
            rsu_id=rsu_id,
            timestamp_unix_ms=int(time.time() * 1000),
            nonce=n,
        )

    def epoch_id(self, window_ms: int = 5000) -> int:
        """由时间戳推导的时间窗口编号（与 PPT 中 epoch 字段语义一致，便于 RSU 策略分区）。"""
        if window_ms <= 0:
            raise ValueError("window_ms 必须为正")
        return self.timestamp_unix_ms // window_ms

    def canonical_bytes(self) -> bytes:
        """
        确定性编码，用作 Dilithium 签名消息与 ZKP 的 message 绑定。
        格式: dom || ver || len(rsu)||rsu || ts_ms(8) || nonce || flags(4)
        """
        dom = b"IoV-Auth-Frame|v1|"
        ver = self.protocol_version
        rid = self.rsu_id
        ts = struct.pack(">Q", self.timestamp_unix_ms & 0xFFFFFFFFFFFFFFFF)
        fl = struct.pack(">I", self.policy_flags & 0xFFFFFFFF)
        return dom + ver + struct.pack(">H", len(rid)) + rid + ts + self.nonce + fl
