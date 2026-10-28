import re
from pathlib import Path

SOC_JS = Path("dashboard/static/soc/js")
js_files = list(SOC_JS.rglob("*.js"))

print(f"Checking imports in {len(js_files)} JS files...")
broken_imports = []

import_regex = re.compile(r'(?:import|from)\s+["\'](\.[^"\']+)["\']')

for js_file in js_files:
    content = js_file.read_text(encoding="utf-8")
    for match in import_regex.finditer(content):
        rel_target = match.group(1)
        # Target file relative to current file's directory
        target_path = (js_file.parent / rel_target).resolve()
        if not target_path.exists():
            broken_imports.append((str(js_file.relative_to(SOC_JS)), rel_target, str(target_path)))

if broken_imports:
    print(f"\nFOUND {len(broken_imports)} BROKEN IMPORTS:")
    for f, imp, resolved in broken_imports:
        print(f"  In {f}: cannot resolve '{imp}' (looked at {resolved})")
else:
    print("All relative JS imports resolved successfully to real files!")

