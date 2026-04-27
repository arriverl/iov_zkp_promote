# -*- coding: utf-8 -*-
"""
后量子认证 (PQC)：基于格的数字签名。
使用 CRYSTALS-Dilithium（dilithium-py）实现，安全性基于 MLWE/ISIS 问题，抗 Shor 量子攻击。
"""
from __future__ import annotations

import time
from typing import Tuple, Optional

# 使用真实 Dilithium 实现（NIST PQC 标准化方案）
try:
    from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5
    from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
    _DILITHIUM_AVAILABLE = True
except ImportError:
    _DILITHIUM_AVAILABLE = False

# 安全级别到类的映射
_DILITHIUM_MAP = {
    2: Dilithium2,
    3: Dilithium3,
    5: Dilithium5,
}
_ML_DSA_MAP = {
    2: ML_DSA_44,   # 对应 NIST level 2
    3: ML_DSA_65,
    5: ML_DSA_87,
}


class PQCLatticeSigner:
    """
    基于格的后量子签名器。
    封装 Dilithium/ML-DSA 的 keygen、sign、verify，用于 OBU 身份绑定与消息完整性。
    """

    def __init__(self, security_level: int = 2, use_ml_dsa: bool = False):
        if not _DILITHIUM_AVAILABLE:
            raise RuntimeError(
                "dilithium-py 未安装。请执行: pip install dilithium-py"
            )
        if security_level not in (2, 3, 5):
            raise ValueError("security_level 必须为 2, 3 或 5")
        self.security_level = security_level
        self.use_ml_dsa = use_ml_dsa
        cls = _ML_DSA_MAP[security_level] if use_ml_dsa else _DILITHIUM_MAP[security_level]
        self._scheme = cls
        self._pk: Optional[bytes] = None
        self._sk: Optional[bytes] = None

    def keygen(self) -> Tuple[bytes, bytes]:
        """生成 (pk, sk)。"""
        pk, sk = self._scheme.keygen()
        self._pk = pk
        self._sk = sk
        return pk, sk

    def sign(self, message: bytes, sk: Optional[bytes] = None) -> bytes:
        """对 message 签名，返回签名字节。"""
        secret = sk if sk is not None else self._sk
        if secret is None:
            raise RuntimeError("未设置私钥，请先 keygen() 或 set_sk()")
        return self._scheme.sign(secret, message)

    def verify(
        self,
        message: bytes,
        signature: bytes,
        pk: Optional[bytes] = None,
    ) -> bool:
        """验证 (message, signature) 与公钥 pk。"""
        public = pk if pk is not None else self._pk
        if public is None:
            raise RuntimeError("未设置公钥")
        return self._scheme.verify(public, message, signature)

    def set_keypair(self, pk: bytes, sk: bytes) -> None:
        self._pk = pk
        self._sk = sk

    @property
    def public_key_bytes(self) -> int:
        """公钥典型长度（字节），用于通信开销估算。"""
        pk, _ = self._scheme.keygen()
        return len(pk)

    @property
    def signature_bytes(self) -> int:
        """签名典型长度（字节）。"""
        _, sk = self._scheme.keygen()
        sig = self._scheme.sign(sk, b"")
        return len(sig)


def measure_pqc_latency(
    security_level: int = 2,
    message: bytes = b"Auth_Request_bench",
    rounds: int = 100,
) -> dict:
    """
    测量 PQC 模块的 keygen/sign/verify 延迟（毫秒）。
    用于与报告中的 ~15ms 总认证延迟对比。
    """
    if not _DILITHIUM_AVAILABLE:
        return {"error": "dilithium-py not installed"}
    signer = PQCLatticeSigner(security_level=security_level)
    pk, sk = signer.keygen()

    keygen_times = []
    sign_times = []
    verify_times = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        _pk, _sk = signer._scheme.keygen()
        keygen_times.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        sig = signer._scheme.sign(sk, message)
        sign_times.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        signer._scheme.verify(pk, message, sig)
        verify_times.append((time.perf_counter() - t0) * 1000)

    import statistics
    return {
        "keygen_ms_mean": statistics.mean(keygen_times),
        "keygen_ms_median": statistics.median(keygen_times),
        "sign_ms_mean": statistics.mean(sign_times),
        "sign_ms_median": statistics.median(sign_times),
        "verify_ms_mean": statistics.mean(verify_times),
        "verify_ms_median": statistics.median(verify_times),
        "pk_bytes": len(pk),
        "sig_bytes": len(sig),
    }
