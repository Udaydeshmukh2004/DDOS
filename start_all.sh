#!/bin/bash
# IntelliShield SDN — Master Service Starter
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "============================================================"
echo "  Starting IntelliShield SDN Core Services"
echo "============================================================"

# 1. Clean stale Mininet / OVS state
sudo mn -c 2>/dev/null || true

# 2. Kill any stale instances
pkill -f 'osken-manager' 2>/dev/null || true
pkill -f 'dashboard/api.py' 2>/dev/null || true
sleep 1

# 3. Start OsKen SDN Flow Monitor Controller
echo "[1/2] Starting OsKen Controller (ports 6633, 6653)..."
nohup .venv/bin/osken-manager controller/flow_monitor.py > logs/controller.log 2>&1 &
CTRL_PID=$!
echo "      Controller PID: $CTRL_PID"

# 4. Start Dashboard Backend API Server
echo "[2/2] Starting Dashboard API Server (port 8080)..."
nohup .venv/bin/python dashboard/api.py > logs/dashboard_api.log 2>&1 &
DASH_PID=$!
echo "      Dashboard API PID: $DASH_PID"

echo "Waiting for services to initialize..."
sleep 5

echo "============================================================"
echo "  Active Services Status:"
echo "============================================================"
ps aux | grep -E 'osken|dashboard/api.py' | grep -v grep || true
echo "============================================================"
echo "  Network Ports:"
netstat -tuln | grep -E '8080|6633|6653' || true
echo "============================================================"
echo "  Access Dashboard: http://127.0.0.1:8080"
echo "  SOC Command Ctr : http://127.0.0.1:8080/soc/"
echo "============================================================"

