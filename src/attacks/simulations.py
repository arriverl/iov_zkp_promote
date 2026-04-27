# -*- coding: utf-8 -*-
from __future__ import annotations

import statistics
from typing import Dict, List

import numpy as np

from ..protocol import FusionAuthProtocol, IoVAuthFrame


def _fresh_request(protocol: FusionAuthProtocol, rsu_id: bytes = b"RSU-ATTACK") -> dict:
    frame = IoVAuthFrame.fresh(rsu_id)
    return protocol.obu_build_request(frame=frame)


def run_attack_suite(rounds: int = 30) -> List[Dict[str, float]]:
    protocol = FusionAuthProtocol()
    protocol.obu_setup()

    results: List[Dict[str, float]] = []

    # 1) 重放攻击：同一请求重复发送
    req = _fresh_request(protocol)
    baseline = protocol.rsu_verify(req).success
    replay_success = 0
    for _ in range(rounds):
        replay_success += int(protocol.rsu_verify(req).success)
    results.append({
        "attack": "replay",
        "success_rate": replay_success / rounds,
        "notes": 1.0 if baseline else 0.0,
    })

    # 2) 证书窃取/远程冒充：用合法请求，但 RSU 测得CSI为异地随机
    theft_success = 0
    for _ in range(rounds):
        req = _fresh_request(protocol)
        fake_remote_csi = protocol.pls.extract_csi_fingerprint(seed=np.random.randint(1, 10_000))
        theft_success += int(protocol.rsu_verify(req, measured_csi=fake_remote_csi).success)
    results.append({
        "attack": "certificate_theft_impersonation",
        "success_rate": theft_success / rounds,
        "notes": 0.0,
    })

    # 3) 远程中继：模拟中继导致CSI额外失真
    relay_success = 0
    similarities = []
    for _ in range(rounds):
        req = _fresh_request(protocol)
        relay_csi = protocol.pls.add_channel_noise(req["reported_csi"], noise_std=0.35)
        r = protocol.rsu_verify(req, measured_csi=relay_csi)
        relay_success += int(r.success)
        similarities.append(r.pls_similarity)
    results.append({
        "attack": "remote_relay",
        "success_rate": relay_success / rounds,
        "notes": statistics.mean(similarities) if similarities else 0.0,
    })

    # 4) 篡改攻击：中间人篡改 message，保持原签名
    tamper_success = 0
    for _ in range(rounds):
        req = _fresh_request(protocol)
        req2 = dict(req)
        req2["message"] = req["message"] + b"|MITM"
        tamper_success += int(protocol.rsu_verify(req2).success)
    results.append({
        "attack": "message_tampering_mitm",
        "success_rate": tamper_success / rounds,
        "notes": 0.0,
    })

    return results
