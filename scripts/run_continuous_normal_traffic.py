#!/usr/bin/env python3
"""
IntelliShield SDN — Continuous Normal Traffic Generator Runner

Starts a Mininet topology connected to the running OsKen controller
and generates steady, realistic benign background traffic indefinitely
(or for a specified duration) until interrupted.

Traffic Profiles Included:
    1. Multi-host ICMP ring (h1->h2->h3->h4->h5->h1) at regular intervals
    2. Periodic lightweight HTTP GET requests from client hosts to h2:80
    3. Low-rate UDP datagrams simulating DNS/telemetry

Usage:
    sudo python3 scripts/run_continuous_normal_traffic.py
    sudo python3 scripts/run_continuous_normal_traffic.py --interval 0.5 --duration 300
    sudo python3 scripts/run_continuous_normal_traffic.py --controller-port 6653
"""

import os
import sys
import time
import signal
import argparse
import logging
import traceback
import subprocess
from typing import Dict, List, Any

# Ensure project root in sys.path
_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "scripts" else _FILE_DIR
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from traffic_generator.traffic_profiles import CONTROLLER_HOST, CONTROLLER_PORT
from traffic_generator.normal_traffic import NormalTrafficGenerator
from traffic_generator.traffic_logger import init_traffic_logs, log_traffic_event

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("continuous_normal_traffic")

try:
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.clean import cleanup as mininet_cleanup
    from mininet.log import setLogLevel
    _MININET_OK = True
except ImportError:
    _MININET_OK = False


def cleanup_stale_processes():
    """Kill lingering traffic generators and stale OVS bridges."""
    logger.info("Cleaning up any stale Mininet/traffic processes...")
    try:
        subprocess.run(
            ["pkill", "-9", "-f", "ping"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["pkill", "-9", "-f", "iperf"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["pkill", "-9", "-f", "http.server"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if _MININET_OK:
            mininet_cleanup()
    except Exception as e:
        logger.warning("Cleanup warning: %s", e)
    time.sleep(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run continuous benign normal traffic in Mininet."
    )
    parser.add_argument(
        "--hosts", "-n", type=int, default=5,
        help="Number of Mininet hosts (default: 5).",
    )
    parser.add_argument(
        "--controller-ip", type=str, default=CONTROLLER_HOST,
        help=f"SDN controller IP (default: {CONTROLLER_HOST}).",
    )
    parser.add_argument(
        "--controller-port", "-p", type=int, default=CONTROLLER_PORT,
        help=f"SDN controller OpenFlow port (default: {CONTROLLER_PORT}).",
    )
    parser.add_argument(
        "--interval", "-i", type=float, default=0.5,
        help="Seconds between ICMP ping packets (default: 0.5s = 2 pkts/s).",
    )
    parser.add_argument(
        "--duration", "-d", type=int, default=0,
        help="Duration in seconds to run (default: 0 = continuous indefinitely).",
    )
    parser.add_argument(
        "--http-interval", type=float, default=3.0,
        help="Seconds between benign HTTP requests (default: 3.0s).",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not _MININET_OK:
        logger.error("Mininet is not installed or importable. Run this on Ubuntu/WSL with Mininet.")
        sys.exit(1)

    print("\n" + "=" * 65)
    print("  IntelliShield SDN — Continuous Normal Traffic Engine")
    print(f"  Target Controller: {args.controller_ip}:{args.controller_port}")
    print(f"  Topology         : 1 Switch (s1) + {args.hosts} Hosts (h1..h{args.hosts})")
    print(f"  Ping Interval    : {args.interval}s per ring link")
    print(f"  Mode             : {'CONTINUOUS (indefinite)' if args.duration <= 0 else f'{args.duration}s timed'}")
    print("=" * 65 + "\n")

    cleanup_stale_processes()
    init_traffic_logs()

    setLogLevel("warning")

    logger.info("Instantiating Mininet network...")
    net = Mininet(
        switch=OVSSwitch,
        autoSetMacs=True,
    )
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip=args.controller_ip,
        port=args.controller_port,
    )

    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    hosts = []
    for i in range(1, args.hosts + 1):
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}")
        net.addLink(h, s1)
        hosts.append(h)

    logger.info("Starting Mininet network with switch s1 connecting to controller...")
    net.start()
    time.sleep(2)  # Wait for switch handshake and table-miss flow installation

    # Verify initial connectivity
    logger.info("Testing initial connectivity between hosts (pingAll)...")
    loss = net.pingAll(timeout="2")
    logger.info("Ping connectivity loss: %.1f%%", loss)

    # Start lightweight HTTP server on h2
    h2 = net.get("h2")
    h2.cmd("python3 -m http.server 80 > /dev/null 2>&1 & echo $! > /tmp/h2_norm_http.pid")
    time.sleep(1)

    # Register signal handler for clean shutdown
    stop_flag = False

    def handle_signal(sig, frame):
        nonlocal stop_flag
        print("\n")
        logger.info("Received termination signal. Stopping continuous traffic...")
        stop_flag = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    host_names = [h.name for h in hosts]
    gen = NormalTrafficGenerator(net)

    logger.info("Starting continuous ICMP ring traffic across hosts %s...", host_names)
    for i in range(len(host_names)):
        src = host_names[i]
        dst = host_names[(i + 1) % len(host_names)]
        gen.generate_continuous_icmp(src, dst, interval=args.interval)

    log_traffic_event(
        traffic_type="CONTINUOUS_NORMAL_BASELINE",
        source="ring_all",
        destination="ring_all",
        protocol="ICMP+HTTP",
        packet_rate=round(len(host_names) / args.interval, 2),
        duration=-1 if args.duration <= 0 else args.duration,
        status="RUNNING",
    )

    start_time = time.time()
    last_http_time = start_time
    last_status_time = start_time

    logger.info("Normal packets are now flowing continuously! Press Ctrl+C to stop.")

    try:
        while not stop_flag:
            now = time.time()
            elapsed = int(now - start_time)

            if args.duration > 0 and elapsed >= args.duration:
                logger.info("Specified duration of %ds reached. Stopping.", args.duration)
                break

            # Periodic HTTP requests from h3, h4, h5 to h2:80
            if now - last_http_time >= args.http_interval:
                for client_name in ["h3", "h4", "h5"]:
                    if client_name in host_names:
                        c_host = net.get(client_name)
                        c_host.cmd("curl -s -m 1 http://10.0.0.2:80/ > /dev/null 2>&1 &")
                last_http_time = now

            # Periodic status log every 10 seconds
            if now - last_status_time >= 10.0:
                logger.info(
                    "[ACTIVE] Continuous normal packets flowing | Elapsed: %ds | Mode: ICMP ring + HTTP",
                    elapsed,
                )
                last_status_time = now

            time.sleep(0.5)

    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
    except Exception as exc:
        logger.error("Exception during traffic generation:\n%s", traceback.format_exc())
    finally:
        logger.info("Stopping all traffic and cleaning up Mininet...")
        try:
            gen.stop_all_traffic(host_names)
        except Exception:
            pass
        try:
            h2.cmd("kill -9 $(cat /tmp/h2_norm_http.pid 2>/dev/null) 2>/dev/null")
            h2.cmd("rm -f /tmp/h2_norm_http.pid")
        except Exception:
            pass
        try:
            net.stop()
            logger.info("Mininet network stopped.")
        except Exception:
            pass
        cleanup_stale_processes()
        log_traffic_event("CONTINUOUS_NORMAL_BASELINE", "all", "all", "ALL", status="STOPPED")
        logger.info("Continuous normal traffic session cleanly terminated.")


if __name__ == "__main__":
    main()
