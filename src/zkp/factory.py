# -*- coding: utf-8 -*-
"""ZKP 证明系统工厂。"""
from __future__ import annotations

from typing import Literal, Tuple

import numpy as np

from .sigma_proof import ZKPProver, ZKPVerifier, ZKProof
from .sis_lattice_nizk import SISLatticeNIZKProver, SISLatticeNIZKVerifier

ZKPMode = Literal["sigma", "sis_lattice_nizk"]

# pczkp 已弃用（属上下文拼接，非算法创新）；保留导入供历史对照实验可选
try:
    from .pls_coupled_zkp import PCZKPProver, PCZKPVerifier  # noqa: F401
    _HAS_PCZKP = True
except ImportError:
    _HAS_PCZKP = False


def create_zkp_system(
    mode: str = "sis_lattice_nizk",
    challenge_bytes: int = 16,
    epoch_window_ms: int = 5000,
) -> Tuple[object, object]:
    if mode == "sis_lattice_nizk":
        return (
            SISLatticeNIZKProver(challenge_bytes=challenge_bytes),
            SISLatticeNIZKVerifier(challenge_bytes=challenge_bytes),
        )
    if mode == "pczkp" and _HAS_PCZKP:
        from .pls_coupled_zkp import PCZKPProver, PCZKPVerifier
        return (
            PCZKPProver(challenge_bytes=challenge_bytes, epoch_window_ms=epoch_window_ms),
            PCZKPVerifier(challenge_bytes=challenge_bytes, epoch_window_ms=epoch_window_ms),
        )
    return ZKPProver(challenge_bytes=challenge_bytes), ZKPVerifier(challenge_bytes=challenge_bytes)


def prove_request(
    prover: object,
    witness: bytes,
    public_input: bytes,
    message: bytes,
    reported_csi: np.ndarray,
) -> ZKProof:
    if isinstance(prover, SISLatticeNIZKProver):
        return prover.prove(witness, public_input, message)
    if type(prover).__name__ == "PCZKPProver":
        return prover.prove(witness, public_input, message, reported_csi)
    return prover.prove(witness, public_input, message)


def verify_request(
    verifier: object,
    public_input: bytes,
    message: bytes,
    proof: ZKProof,
    reported_csi: np.ndarray,
) -> bool:
    if isinstance(verifier, SISLatticeNIZKVerifier):
        return verifier.verify(public_input, message, proof)
    if type(verifier).__name__ == "PCZKPVerifier":
        return verifier.verify(public_input, message, proof, reported_csi)
    return verifier.verify(public_input, message, proof)
