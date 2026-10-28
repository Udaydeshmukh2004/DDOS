#!/bin/bash
# IntelliShield SDN — Stop All Services
echo "Stopping IntelliShield SDN Services..."
pkill -f 'dashboard/api.py' 2>/dev/null || true
pkill -f 'osken-manager' 2>/dev/null || true
pkill -f 'traffic_scheduler' 2>/dev/null || true
pkill -f 'run_continuous_normal_traffic' 2>/dev/null || true
sudo mn -c 2>/dev/null || true
echo "All services stopped."

