import urllib.request
import json

BASE = "http://127.0.0.1:8080"
ENDPOINTS = [
    "/",
    "/soc/css/soc.css",
    "/soc/js/app.js",
    "/api/status",
    "/api/summary",
    "/api/traffic?n=60",
    "/api/entropy?n=60",
    "/api/alerts?n=25",
    "/api/security-alerts?limit=15",
    "/api/security-alerts/stats",
    "/api/correlation-results?limit=15",
    "/api/fused-decisions?limit=15",
    "/api/verification-results?limit=15",
    "/api/root-cause-reports?limit=15",
    "/api/mitigation/blocklist",
    "/api/ml?n=40",
    "/api/digital-twin/stats",
    "/api/digital-twin/snapshots?limit=5",
    "/api/control/status",
    "/api/automl/status",
    "/api/alerts/email/status",
    "/api/topology",
]

print(f"Checking endpoints on {BASE}...")
errors = []
for ep in ENDPOINTS:
    url = BASE + ep
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            code = resp.status
            content_type = resp.headers.get("content-type", "")
            data = resp.read()
            print(f"  [OK] {ep:35} -> HTTP {code} ({content_type}, {len(data)} bytes)")
    except urllib.error.HTTPError as e:
        print(f"  [FAIL] {ep:35} -> HTTP {e.code}")
        errors.append((ep, f"HTTP {e.code}"))
    except Exception as e:
        print(f"  [FAIL] {ep:35} -> {e}")
        errors.append((ep, str(e)))

if errors:
    print(f"\n{len(errors)} endpoints FAILED!")
else:
    print("\nAll tested endpoints returned HTTP 200 OK!")

