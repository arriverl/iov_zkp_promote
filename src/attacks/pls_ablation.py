# -*- coding: utf-8 -*-
"""
盗证场景 PLS 消融：主实验启用物理层校验；对照组显式关闭校验并标注为 counterfactual。

威胁模型（两组相同）：
  攻击者持有受害者完整合法凭证（ZKP + PQC + reported_csi），在异地 RSU 发起认证；
  RSU 侧信道测量为异地 CSI（``extract_remote_csi``）。

主实验（primary）：``pls_enabled=True`` → 物理层拦截盗证。
对照组（control）：``pls_enabled=False`` → 模拟 Yang/ECDH 等无 PLS 方案，仅验密码学层。
"""
from __future__ import annotations

from typing import Dict, List

from ..protocol import FusionAuthProtocol, IoVAuthFrame

_THEFT_THREAT = (
    "stolen_credentials_remote_rsu: attacker replays legal ZKP+PQC+reported_csi "
    "while RSU measures foreign-channel CSI"
)
_CONTROL_NOTE = (
    "CONTROL(counterfactual): pls_verification=disabled — simulates legacy crypto-only "
    "schemes without physical-layer second factor; not a security breach of full protocol"
)
_PRIMARY_NOTE = (
    "PRIMARY: pls_verification=enabled — RSU compares reported vs measured CSI; "
    "theft blocked when channels differ"
)


def run_pls_theft_ablation(
    rounds: int = 30,
    protocol: FusionAuthProtocol | None = None,
) -> List[Dict[str, object]]:
    p = protocol or FusionAuthProtocol()
    p.obu_setup()

    with_pls_ok = 0
    control_ok = 0

    for _ in range(rounds):
        # 主实验与对照组各用独立会话，避免 Replay Guard 将第二次验证判为重放
        frame_primary = IoVAuthFrame.fresh(b"RSU-THEFT-ABL")
        req_primary = p.obu_build_request(frame=frame_primary)
        remote_primary = p.pls.extract_remote_csi(req_primary["message"])
        if p.rsu_verify(req_primary, measured_csi=remote_primary, pls_enabled=True).success:
            with_pls_ok += 1

        frame_control = IoVAuthFrame.fresh(b"RSU-THEFT-CTL")
        req_control = p.obu_build_request(frame=frame_control)
        remote_control = p.pls.extract_remote_csi(req_control["message"])
        if p.rsu_verify(req_control, measured_csi=remote_control, pls_enabled=False).success:
            control_ok += 1

    rate_primary = with_pls_ok / rounds
    rate_control = control_ok / rounds

    return [
        {
            "scenario": "certificate_theft_with_pls",
            "experiment_role": "primary",
            "pls_verification": "enabled",
            "threat_model": _THEFT_THREAT,
            "note": _PRIMARY_NOTE,
            "auth_success_rate": rate_primary,
            "rounds": float(rounds),
        },
        {
            "scenario": "control_crypto_only_without_pls",
            "experiment_role": "control_counterfactual",
            "pls_verification": "disabled",
            "threat_model": _THEFT_THREAT,
            "note": _CONTROL_NOTE,
            "auth_success_rate": rate_control,
            "rounds": float(rounds),
        },
    ]
