from pathlib import Path
import re

api_py = Path("dashboard/api.py").read_text(encoding="utf-8")
for i, line in enumerate(api_py.splitlines(), 1):
    if line.strip().startswith("@app."):
        print(f"{i:4d}: {line.strip()}")

