#!/usr/bin/env python3
"""
IntelliShield SDN — Frontend-to-Backend Connectivity Verifier
"""

import os
import re
import sys
import json
import urllib.request
import urllib.error
from typing import Dict, List, Set, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML = os.path.join(_ROOT, "dashboard", "static", "index.html")
API_PY = os.path.join(_ROOT, "dashboard", "api.py")
BASE_URL = "http://127.0.0.1:8080"


def get_actual_frontend_calls():
    with open(INDEX_HTML, "r", encoding="utf-8") as f:
        content = f.read()

    calls = set()
    # fetchJSON('/api/...')
    for m in re.findall(r"fetchJSON\(\s*['\"]([^'\"]+)['\"]", content):
        calls.add(m)
    # fetch(API + '...')
    for m in re.findall(r"fetch\(\s*API\s*\+\s*['\"]([^'\"]+)['\"]", content):
        calls.add(m)
    # fetch(`${API}/api/...`)
    for m in re.findall(r"`\$\{API\}(/api/[^`]+)`", content):
        calls.add(m)

    return sorted(calls)


def main():
    actual_calls = get_actual_frontend_calls()
    print("=" * 70)
    print("ACTUAL FRONTEND ENDPOINT CALLS IN index.html:")
    print("=" * 70)
    for c in actual_calls:
        print(f"  {c}")

    print("\n" + "=" * 70)
    print("TESTING EACH ACTUAL CALL AGAINST LIVE BACKEND:")
    print("=" * 70)

    for c in actual_calls:
        url = BASE_URL + c
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read().decode("utf-8")
                try:
                    js = json.loads(data)
                    keys = list(js.keys()) if isinstance(js, dict) else f"list({len(js)})"
                    print(f"  [200 OK]  {c:<35} -> JSON keys: {keys}")
                except Exception:
                    print(f"  [200 OK]  {c:<35} -> Non-JSON ({len(data)} bytes)")
        except urllib.error.HTTPError as err:
            print(f"  [{err.code} ERROR] {c:<35} -> {err.reason}")
        except Exception as exc:
            print(f"  [CONN FAIL] {c:<35} -> {exc}")


if __name__ == "__main__":
    main()

