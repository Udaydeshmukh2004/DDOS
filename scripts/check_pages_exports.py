from pathlib import Path
import re

app_js = Path("dashboard/static/soc/js/app.js").read_text()
pages_index_js = Path("dashboard/static/soc/js/pages/index.js").read_text()

# Find all pages.<func> used in app.js
used_in_app = re.findall(r'pages\.(\w+)', app_js)
print(f"Used in app.js: {set(used_in_app)}")

# Find all export ... in pages/index.js
exported = re.findall(r'export\s+(?:async\s+)?function\s+(\w+)', pages_index_js)
exported += re.findall(r'export\s*\{\s*([^}]+)\s*\}', pages_index_js)

flattened_exported = set()
for item in exported:
    if isinstance(item, str):
        for sub in item.split(','):
            sub = sub.strip().split(' as ')[-1].strip()
            if sub:
                flattened_exported.add(sub)

missing = [f for f in set(used_in_app) if f not in flattened_exported]
print(f"Missing exports: {missing}")

