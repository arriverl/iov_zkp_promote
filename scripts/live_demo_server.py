#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
真算 Live Demo 服务：浏览器调用真实 FusionAuthProtocol，驱动传输可视化。

用法:
    python scripts/live_demo_server.py
    python scripts/live_demo_server.py --profile balanced --port 8765

浏览器打开: http://127.0.0.1:8765/
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from flask import Flask, jsonify, request, send_from_directory
except ImportError as e:
    print("请先安装 Flask: pip install flask>=3.0.0")
    raise SystemExit(1) from e

from src.config import load_profile, protocol_from_config
from src.demo.live_round import run_live_round
from src.demo.metrics_loader import load_experiment_metrics

DEMO_DIR = ROOT / "docs" / "demo"

app = Flask(__name__)
_protocol = None
_profile_name = "balanced"


def get_protocol():
    global _protocol
    if _protocol is None:
        cfg = load_profile(_profile_name)
        _protocol = protocol_from_config(cfg)
        _protocol.obu_setup()
    return _protocol


@app.route("/")
def index():
    return send_from_directory(DEMO_DIR, "showcase.html")


@app.route("/showcase.html")
def showcase_page():
    return send_from_directory(DEMO_DIR, "showcase.html")


@app.route("/traffic.html")
def traffic_page():
    return send_from_directory(DEMO_DIR, "traffic_simulator.html")


@app.route("/report.html")
def report_page():
    return send_from_directory(DEMO_DIR, "index.html")


@app.route("/api/health")
def health():
    return jsonify({"ok": True, "profile": _profile_name, "real_compute": True})


@app.route("/api/round", methods=["POST"])
def api_round():
    data = request.get_json(silent=True) or {}
    scenario = str(data.get("scenario", "normal"))
    allowed = {"normal", "theft", "replay", "tamper", "relay"}
    if scenario not in allowed:
        return jsonify({"error": f"scenario 必须是 {sorted(allowed)}"}), 400
    try:
        proto = get_protocol()
        out = run_live_round(proto, scenario=scenario)
        return jsonify(out)
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


@app.route("/api/metrics")
def api_metrics():
    try:
        return jsonify(load_experiment_metrics())
    except Exception as ex:
        return jsonify({"error": str(ex)}), 500


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """重新 KeyGen（可选）。"""
    global _protocol
    _protocol = None
    get_protocol()
    return jsonify({"ok": True, "message": "协议已重新初始化 obu_setup()"})


def main() -> None:
    parser = argparse.ArgumentParser(description="ZKP-PQC-PLS 真算 Live Demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--profile", default="balanced")
    args = parser.parse_args()

    global _profile_name
    _profile_name = args.profile

    print("=" * 60)
    print("ZKP-PQC-PLS 真算传输演示服务")
    print(f"  配置: configs/{args.profile}.json")
    print(f"  地址: http://{args.host}:{args.port}/")
    print(f"  大屏: http://{args.host}:{args.port}/showcase.html")
    print("  API : POST /api/round  GET /api/metrics")
    print("=" * 60)

    print("[预热] obu_setup() + Dilithium KeyGen...")
    get_protocol()
    print("[就绪] 请在浏览器打开上述地址")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
