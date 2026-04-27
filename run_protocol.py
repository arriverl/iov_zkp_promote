#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZKP-PQC-PLS 融合认证协议：单次运行入口。
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.protocol.fusion_protocol import run_protocol_demo

if __name__ == "__main__":
    run_protocol_demo()
