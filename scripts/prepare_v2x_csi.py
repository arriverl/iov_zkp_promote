# -*- coding: utf-8 -*-
"""
准备 V2X CSI 数据集：
1. 若 data/v2x_csi/raw 含 IEEE .mat → 解析导出
2. 否则生成文献场景校准子集（3GPP Jakes，车速 0/5/10/20/30/40 km/h，对齐 IEEE DataPort 分组）
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.pls.v2x_channel_model import jakes_v2x_csi_amplitude, rsu_measurement

RAW_DIR = ROOT / "data" / "v2x_csi" / "raw"
OUT_DIR = ROOT / "data" / "v2x_csi" / "processed"

SPEEDS_KMH = [0, 5, 10, 20, 30, 40]
# IEEE DataPort V2X CSI 论文中的各速度 CSI 组数量（用于每速度采样数）
GROUP_COUNTS = {0: 23, 5: 137, 10: 45, 20: 28, 30: 15, 40: 96}
CSI_DIM = 32
NOISE_STD = 0.06


def _extract_amp_from_mat(obj) -> np.ndarray | None:
    arr = np.asarray(obj)
    if arr.size < 8:
        return None
    if np.iscomplexobj(arr):
        amp = np.abs(arr).astype(np.float64).ravel()
    else:
        amp = arr.astype(np.float64).ravel()
    if amp.size < 8:
        return None
    return amp


def _try_parse_mat_files(raw_dir: Path, csi_dim: int) -> list[dict] | None:
    try:
        from scipy.io import loadmat
    except ImportError:
        return None

    mats = list(raw_dir.rglob("*.mat"))
    if not mats:
        return None

    pairs: list[dict] = []
    for mi, mat_path in enumerate(mats[:400]):
        try:
            data = loadmat(mat_path, squeeze_me=True, struct_as_record=False)
        except Exception:
            continue
        amps: list[np.ndarray] = []
        for k, v in data.items():
            if k.startswith("__"):
                continue
            amp = _extract_amp_from_mat(v)
            if amp is not None and amp.size >= csi_dim:
                amps.append(amp)
        if len(amps) >= 2:
            obu = amps[0][:csi_dim]
            rsu = amps[1][:csi_dim]
        elif len(amps) == 1:
            obu = amps[0][:csi_dim]
            rsu = obu + np.random.default_rng(mi).normal(0, NOISE_STD, obu.shape)
        else:
            continue
        tag = f"ieee_mat_{mi:04d}"
        pairs.append({"tag": tag, "obu": obu, "rsu": rsu, "speed_kmh": 0})
    return pairs if pairs else None


def _bootstrap_literature_calibrated(csi_dim: int, seed: int = 42) -> tuple[list[dict], list[dict]]:
    rng = np.random.default_rng(seed)
    legit: list[dict] = []
    theft: list[dict] = []
    by_speed: dict[int, list[str]] = {s: [] for s in SPEEDS_KMH}

    for speed, count in GROUP_COUNTS.items():
        n = min(count, max(4, count // 3))
        for j in range(n):
            tag = f"v2x_{speed}kmh_{j:03d}"
            obu = jakes_v2x_csi_amplitude(csi_dim, speed, rng=rng)
            rsu = rsu_measurement(obu, NOISE_STD, rng)
            legit.append({"tag": tag, "obu": obu, "rsu": rsu, "speed_kmh": speed})
            by_speed[speed].append(tag)

    speeds = SPEEDS_KMH
    for si, s_obu in enumerate(speeds):
        for s_rsu in speeds:
            if s_obu == s_rsu:
                continue
            obu_tags = by_speed[s_obu]
            rsu_tags = by_speed[s_rsu]
            if not obu_tags or not rsu_tags:
                continue
            for k in range(min(3, len(obu_tags), len(rsu_tags))):
                theft.append(
                    {
                        "tag": f"theft_{s_obu}to{s_rsu}_{k}",
                        "obu_tag": obu_tags[k % len(obu_tags)],
                        "rsu_tag": rsu_tags[k % len(rsu_tags)],
                        "speed_obu_kmh": s_obu,
                        "speed_rsu_kmh": s_rsu,
                    }
                )
    return legit, theft


def prepare(csi_dim: int = CSI_DIM, force: bool = False) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    idx_path = OUT_DIR / "index.json"
    if idx_path.exists() and not force:
        print(f"[SKIP] 已存在 {idx_path}，使用 --force 重建")
        return OUT_DIR

    source = "literature_calibrated_v2x"
    legit_raw: list[dict] | None = None
    if RAW_DIR.exists():
        legit_raw = _try_parse_mat_files(RAW_DIR, csi_dim)

    if legit_raw:
        source = "ieee_v2x_mat"
        legit_meta = []
        for rec in legit_raw:
            obu_f = f"{rec['tag']}_obu.npy"
            rsu_f = f"{rec['tag']}_rsu.npy"
            np.save(OUT_DIR / obu_f, rec["obu"].astype(np.float32))
            np.save(OUT_DIR / rsu_f, rec["rsu"].astype(np.float32))
            legit_meta.append(
                {"id": rec["tag"], "obu": obu_f, "rsu": rsu_f, "speed_kmh": rec.get("speed_kmh", 0)}
            )
        theft_meta = []
        for i in range(min(60, len(legit_meta))):
            a, b = i, (i + len(legit_meta) // 3 + 1) % len(legit_meta)
            theft_meta.append(
                {
                    "id": f"theft_{i}",
                    "obu": legit_meta[a]["obu"],
                    "rsu_foreign": legit_meta[b]["rsu"],
                }
            )
    else:
        legit_list, theft_list = _bootstrap_literature_calibrated(csi_dim)
        legit_meta = []
        tag_to_files: dict[str, tuple[str, str]] = {}
        for rec in legit_list:
            obu_f = f"{rec['tag']}_obu.npy"
            rsu_f = f"{rec['tag']}_rsu.npy"
            np.save(OUT_DIR / obu_f, rec["obu"])
            np.save(OUT_DIR / rsu_f, rec["rsu"])
            tag_to_files[rec["tag"]] = (obu_f, rsu_f)
            legit_meta.append(
                {"id": rec["tag"], "obu": obu_f, "rsu": rsu_f, "speed_kmh": rec["speed_kmh"]}
            )
        theft_meta = []
        for rec in theft_list:
            obu_f, _ = tag_to_files[rec["obu_tag"]]
            # 盗证 RSU 侧：独立 Jakes 实现，避免与合法 OBU 偶然高相关
            foreign = jakes_v2x_csi_amplitude(
                csi_dim,
                rec["speed_rsu_kmh"],
                rng=np.random.default_rng(hash(rec["tag"]) % (2**32)),
            )
            foreign_f = f"{rec['tag']}_rsu_foreign.npy"
            np.save(OUT_DIR / foreign_f, foreign)
            theft_meta.append(
                {
                    "id": rec["tag"],
                    "obu": obu_f,
                    "rsu_foreign": foreign_f,
                    "speed_obu_kmh": rec["speed_obu_kmh"],
                    "speed_rsu_kmh": rec["speed_rsu_kmh"],
                }
            )

    index = {
        "source": source,
        "reference": "IEEE DataPort 10.21227/3mkx-aq02 (V2X bidirectional CSI) / 3GPP TR 37.885 Jakes",
        "csi_dim": csi_dim,
        "speeds_kmh": SPEEDS_KMH,
        "legitimate_pairs": legit_meta,
        "theft_pairs": theft_meta,
    }
    idx_path.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] {source}: {len(legit_meta)} 合法对, {len(theft_meta)} 盗证对 → {OUT_DIR}")
    return OUT_DIR


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csi-dim", type=int, default=CSI_DIM)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    prepare(csi_dim=args.csi_dim, force=args.force)
