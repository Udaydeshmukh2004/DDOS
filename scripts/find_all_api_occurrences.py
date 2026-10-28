#!/usr/bin/env python3
"""Find all API occurrences in index.html with line numbers and context."""
import re
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML = os.path.join(_ROOT, "dashboard", "static", "index.html")

with open(INDEX_HTML, "r", encoding="utf-8") as f:
    for idx, line in enumerate(f, 1):
        if "/api/" in line:
            print(f"Line {idx:4d}: {line.strip()}")

