# -*- coding: utf-8 -*-
"""
ZKP-PQC-PLS 融合认证协议：集成 PQC 签名、ZKP 匿名证明与 PLS CSI 双因子校验。
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from ..pqc import PQCLatticeSigner
from ..zkp import ZKPProver, ZKPVerifier, ZKProof
from ..pls import PLSAuthenticator
from .iov_auth_frame import IoVAuthFrame


@dataclass
class AuthResult:
    """单次认证结果。"""
    success: bool
    latency_ms: float
    zkp_ok: bool
    pls_ok: bool
    pqc_ok: bool
    pls_similarity: float
    details: str = ""


class FusionAuthProtocol:
    """
    融合认证协议执行器。
    OBU：生成 PQC 密钥、ZKP 证明、提取 CSI，发送认证请求。
    RSU：验证 ZKP、校验 CSI、验证 PQC 签名。
    """

    def __init__(
        self,
        pqc_level: int = 2,
        zkp_challenge_bytes: int = 32,
        pls_threshold: float = 0.85,
        pls_csi_dim: int = 64,
        pls_noise_std: float = 0.05,
        replay_window_ms: int = 5000,
    ):
        self.pqc = PQCLatticeSigner(security_level=pqc_level)
        self.zkp_prover = ZKPProver(challenge_bytes=zkp_challenge_bytes)
        self.zkp_verifier = ZKPVerifier(challenge_bytes=zkp_challenge_bytes)
        self.pls = PLSAuthenticator(
            threshold=pls_threshold,
            csi_dim=pls_csi_dim,
            channel_noise_std=pls_noise_std,
        )
        self._pk: Optional[bytes] = None
        self._sk: Optional[bytes] = None
        self.replay_window_ms = replay_window_ms
        self._seen_message_ts: dict[str, float] = {}

    def _cleanup_replay_cache(self, now_ms: float) -> None:
        if not self._seen_message_ts:
            return
        expire_before = now_ms - float(self.replay_window_ms)
        stale = [k for k, ts in self._seen_message_ts.items() if ts < expire_before]
        for key in stale:
            self._seen_message_ts.pop(key, None)

    def _check_and_mark_replay(self, message: bytes, now_ms: float) -> bool:
        """
        返回 True 表示命中重放。
        使用 message 哈希作为指纹，在 replay_window_ms 窗口内拒绝重复请求。
        """
        self._cleanup_replay_cache(now_ms)
        msg_id = hashlib.sha256(message).hexdigest()
        if msg_id in self._seen_message_ts:
            return True
        self._seen_message_ts[msg_id] = now_ms
        return False

    def obu_setup(self) -> Tuple[bytes, bytes]:
        """OBU 侧：生成 PQC 密钥对。"""
        pk, sk = self.pqc.keygen()
        self._pk = pk
        self._sk = sk
        return pk, sk

    def _resolve_message(
        self,
        message: Optional[bytes],
        frame: Optional[IoVAuthFrame],
    ) -> bytes:
        if frame is not None:
            return frame.canonical_bytes()
        if message is None:
            return f"Auth_Request_{int(time.time() * 1000)}".encode("utf-8")
        return message

    def obu_build_request(
        self,
        message: Optional[bytes] = None,
        *,
        frame: Optional[IoVAuthFrame] = None,
    ) -> dict:
        """
        OBU 构建认证请求：ZKP 证明 + PQC 签名 + 上报 CSI。
        若传入 ``frame``（推荐），则签名与 ZKP 的 message 绑定为 ``frame.canonical_bytes()``，
        与 V2X 风格 RSU 挑战、时间窗、nonce 一致，降低重放风险。
        """
        if self._sk is None or self._pk is None:
            self.obu_setup()
        pk, sk = self._pk, self._sk
        msg = self._resolve_message(message, frame)

        # 1) ZKP：证明拥有与 pk 对应的私钥（public_input = pk）
        proof = self.zkp_prover.prove(
            witness=sk,
            public_input=pk,
            message=msg,
        )

        # 2) PQC 签名
        signature = self.pqc.sign(msg, sk)

        # 3) CSI 指纹
        csi = self.pls.extract_csi_fingerprint()

        return {
            "message": msg,
            "pk": pk,
            "zkp_commitment": proof.commitment,
            "zkp_response": proof.response,
            "zkp_challenge_digest": proof.challenge_digest,
            "signature": signature,
            "reported_csi": csi,
        }

    def rsu_verify(
        self,
        request: dict,
        measured_csi: Optional[bytes] = None,
    ) -> AuthResult:
        """
        RSU 侧：验证 ZKP、PQC 签名，并做 CSI 匹配。
        若未提供 measured_csi，则用 reported_csi 加噪声模拟 RSU 测量。
        """
        t0 = time.perf_counter()
        msg = request["message"]
        pk = request["pk"]
        now_ms = time.time() * 1000.0

        if self._check_and_mark_replay(msg, now_ms):
            latency_ms = (time.perf_counter() - t0) * 1000
            return AuthResult(
                success=False,
                latency_ms=latency_ms,
                zkp_ok=False,
                pls_ok=False,
                pqc_ok=False,
                pls_similarity=0.0,
                details="REJECTED: replay detected",
            )

        zkp_ok = self.zkp_verifier.verify(
            request["pk"],
            msg,
            ZKProof(
                commitment=request["zkp_commitment"],
                response=request["zkp_response"],
                challenge_digest=request["zkp_challenge_digest"],
            ),
        )
        pqc_ok = self.pqc.verify(msg, request["signature"], pk)

        reported_csi = request["reported_csi"]
        if measured_csi is not None:
            import numpy as np
            if isinstance(measured_csi, bytes):
                measured_csi = np.frombuffer(measured_csi, dtype=np.float64)
            measured = measured_csi
        else:
            measured = self.pls.add_channel_noise(reported_csi)
        pls_ok, similarity = self.pls.authenticate(reported_csi, measured)

        latency_ms = (time.perf_counter() - t0) * 1000
        success = zkp_ok and pls_ok and pqc_ok
        details = (
            f"ZKP={'PASS' if zkp_ok else 'FAIL'}, "
            f"PQC={'PASS' if pqc_ok else 'FAIL'}, "
            f"PLS={'PASS' if pls_ok else 'FAIL'} (ρ={similarity:.4f})"
        )
        return AuthResult(
            success=success,
            latency_ms=latency_ms,
            zkp_ok=zkp_ok,
            pls_ok=pls_ok,
            pqc_ok=pqc_ok,
            pls_similarity=float(similarity),
            details=details,
        )

    def run_round(
        self,
        message: Optional[bytes] = None,
        *,
        frame: Optional[IoVAuthFrame] = None,
    ) -> AuthResult:
        """执行一轮完整认证（OBU 建请求 → RSU 验证）。"""
        req = self.obu_build_request(message, frame=frame)
        # 序列化 CSI 以便在“信道”上传输；RSU 侧用请求中的 reported_csi 加噪声模拟
        return self.rsu_verify(req)


def run_protocol_demo() -> None:
    """控制台演示一次融合认证。"""
    print("\n--- ZKP-PQC-PLS 融合认证协议 演示 ---\n")
    protocol = FusionAuthProtocol()
    protocol.obu_setup()
    frm = IoVAuthFrame.fresh(b"RSU-DEMO-001")
    print("[OBU] 生成 PQC 密钥、ZKP 证明与 CSI 指纹（绑定 IoVAuthFrame）...")
    req = protocol.obu_build_request(frame=frm)
    print("[RSU] 验证 ZKP、PQC 签名与 PLS 指纹...")
    result = protocol.rsu_verify(req)
    print(f"  认证结果: {'通过' if result.success else '未通过'}")
    print(f"  延迟: {result.latency_ms:.2f} ms")
    print(f"  详情: {result.details}")
    print("--- 演示结束 ---\n")


if __name__ == "__main__":
    run_protocol_demo()
