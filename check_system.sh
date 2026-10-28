#!/bin/bash
# IntelliShield SDN — Complete System Health Diagnostic
echo "============================================================"
echo "  IntelliShield SDN System Health Diagnostic"
echo "============================================================"
echo "[1] System Resource Usage:"
free -h
df -h / | tail -n 1
echo ""
echo "[2] Core Running Processes:"
ps aux | grep -E 'osken|flow_monitor|dashboard/api.py|ovs' | grep -v grep || echo "No SDN services running."
echo ""
echo "[3] Network Ports (8080, 6633, 6653):"
netstat -tuln | grep -E '8080|6633|6653' || echo "Ports are not listening."
echo ""
echo "[4] Open vSwitch Status:"
sudo ovs-vsctl show 2>/dev/null || echo "OVS not responding."
echo "============================================================"

