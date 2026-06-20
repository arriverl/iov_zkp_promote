# -*- coding: utf-8 -*-
"""加载 data/v2x_csi/processed 中的真实/文献校准 V2X CSI 对。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = ROOT / "data" / "v2x_csi" / "processed"


class RealCSIRepository:
    """IEEE V2X CSI 或文献校准子集的索引与采样。"""

    def __init__(self, data_dir: Optional[Path] = None, csi_dim: int = 32):
        self.data_dir = Path(data_dir or DEFAULT_DATA_DIR)
        self.csi_dim = csi_dim
        self._index: Dict = {}
        self._legit: List[Dict] = []
        self._theft: List[Dict] = []
        self._load()

    @property
    def available(self) -> bool:
        return bool(self._legit)

    @property
    def source(self) -> str:
        return str(self._index.get("source", "unknown"))

    def _load(self) -> None:
        idx_path = self.data_dir / "index.json"
        if not idx_path.exists():
            return
        self._index = json.loads(idx_path.read_text(encoding="utf-8"))
        self._legit = list(self._index.get("legitimate_pairs", []))
        self._theft = list(self._index.get("theft_pairs", []))

    def _read_vec(self, rel: str) -> np.ndarray:
        path = self.data_dir / rel
        vec = np.load(path).astype(np.float32).ravel()
        if vec.size != self.csi_dim:
            if vec.size > self.csi_dim:
                vec = vec[: self.csi_dim]
            else:
                pad = np.zeros(self.csi_dim - vec.size, dtype=np.float32)
                vec = np.concatenate([vec, pad])
        n = float(np.linalg.norm(vec)) + 1e-9
        return (vec / n).astype(np.float32)

    def pick_legitimate(self, session_key: bytes) -> Tuple[np.ndarray, np.ndarray]:
        """同链路合法对：OBU 上报 + RSU 测量。"""
        if not self._legit:
            raise FileNotFoundError(f"无 CSI 数据: {self.data_dir}")
        i = int.from_bytes(session_key[:4], "big") % len(self._legit)
        rec = self._legit[i]
        obu = self._read_vec(rec["obu"])
        rsu = self._read_vec(rec["rsu"])
        return obu, rsu

    def pick_theft(self, session_key: bytes) -> Tuple[np.ndarray, np.ndarray]:
        """盗证：合法 OBU 向量 + 异地/跨场景 RSU 向量。"""
        if self._theft:
            i = int.from_bytes(session_key[4:8], "big") % len(self._theft)
            rec = self._theft[i]
            return self._read_vec(rec["obu"]), self._read_vec(rec["rsu_foreign"])
        # 回退：合法 obu + 另一合法对的 rsu
        obu, _ = self.pick_legitimate(session_key)
        _, rsu_foreign = self.pick_legitimate(session_key + b"|THEFT")
        return obu, rsu_foreign

    def summary(self) -> Dict[str, object]:
        return {
            "data_dir": str(self.data_dir),
            "source": self.source,
            "legitimate_pairs": len(self._legit),
            "theft_pairs": len(self._theft),
            "csi_dim": self.csi_dim,
        }
