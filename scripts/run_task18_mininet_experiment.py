#!/usr/bin/env python3
"""
IntelliShield SDN — Task 18: Independent Mininet Experiment Runner
Executes an isolated, authorized lab experiment generating benign traffic and
several controlled attack types supported by the Mininet topology.
Captures actual packet telemetry and records ground-truth schedule timestamps.
"""

import os
import sys
import time
import json
import socket
import struct
import logging
import threading
import subprocess
from datetime import datetime
from typing import Dict, List, Any

# Ensure project root in sys.path
_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "scripts" else _FILE_DIR
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

DATA_DIR = os.path.join(_ROOT, "data", "task18_mininet")
RAW_DIR = os.path.join(DATA_DIR, "raw")
RESULTS_DIR = os.path.join(_ROOT, "results", "task18_unseen_capture")
REPORTS_DIR = os.path.join(_ROOT, "reports")

os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

RAW_PACKETS_CSV = os.path.join(RAW_DIR, "raw_packet_stream.csv")
SCHEDULE_JSON = os.path.join(RAW_DIR, "experiment_schedule.json")
EVENTS_LOG = os.path.join(RAW_DIR, "experiment_events.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(EVENTS_LOG, mode="w"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("task18_experiment")

# Mininet imports
try:
    from mininet.net import Mininet
    from mininet.node import OVSSwitch
    from mininet.clean import cleanup as mininet_cleanup
    _MININET_OK = True
except ImportError:
    _MININET_OK = False


class PacketTelemetrySniffer:
    """Sniffs raw Ethernet frames on Mininet switch interfaces and extracts telemetry."""

    def __init__(self, interfaces: List[str]):
        self.interfaces = interfaces
        self.packets: List[Dict[str, Any]] = []
        self.stop_event = threading.Event()
        self.threads: List[threading.Thread] = []
        self.lock = threading.Lock()

    def _sniff_interface(self, iface: str):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((iface, 0))
            sock.settimeout(0.5)
        except Exception as e:
            logger.error("Failed to bind socket on %s: %e", iface, e)
            return

        while not self.stop_event.is_set():
            try:
                raw_data, _ = sock.recvfrom(2048)
                t_arrival = time.time()
                pkt_len = len(raw_data)

                if pkt_len < 14:
                    continue

                eth_type = struct.unpack("!H", raw_data[12:14])[0]
                eth_src = ":".join(f"{b:02x}" for b in raw_data[6:12])
                eth_dst = ":".join(f"{b:02x}" for b in raw_data[0:6])

                src_ip, dst_ip, proto = "", "", ""
                src_port, dst_port, tcp_flags = 0, 0, ""

                if eth_type == 0x0800 and pkt_len >= 34:  # IPv4
                    ihl = (raw_data[14] & 0x0F) * 4
                    if pkt_len >= 14 + ihl:
                        ip_proto_num = raw_data[23]
                        src_ip = socket.inet_ntoa(raw_data[26:30])
                        dst_ip = socket.inet_ntoa(raw_data[30:34])

                        transport_offset = 14 + ihl
                        if ip_proto_num == 6 and pkt_len >= transport_offset + 20:  # TCP
                            proto = "TCP"
                            src_port, dst_port = struct.unpack("!HH", raw_data[transport_offset:transport_offset + 4])
                            flags_byte = raw_data[transport_offset + 13]
                            flag_names = []
                            if flags_byte & 0x02: flag_names.append("SYN")
                            if flags_byte & 0x10: flag_names.append("ACK")
                            if flags_byte & 0x01: flag_names.append("FIN")
                            if flags_byte & 0x04: flag_names.append("RST")
                            if flags_byte & 0x08: flag_names.append("PSH")
                            if flags_byte & 0x20: flag_names.append("URG")
                            tcp_flags = "|".join(flag_names)
                        elif ip_proto_num == 17 and pkt_len >= transport_offset + 8:  # UDP
                            proto = "UDP"
                            src_port, dst_port = struct.unpack("!HH", raw_data[transport_offset:transport_offset + 4])
                        elif ip_proto_num == 1 and pkt_len >= transport_offset + 4:  # ICMP
                            proto = "ICMP"
                            icmp_type, icmp_code = struct.unpack("!BB", raw_data[transport_offset:transport_offset + 2])
                            tcp_flags = f"TYPE_{icmp_type}_CODE_{icmp_code}"
                        else:
                            proto = f"IP_{ip_proto_num}"
                elif eth_type == 0x0806:
                    proto = "ARP"
                else:
                    proto = f"ETH_0x{eth_type:04x}"

                rec = {
                    "timestamp": t_arrival,
                    "interface": iface,
                    "packet_length": pkt_len,
                    "eth_src": eth_src,
                    "eth_dst": eth_dst,
                    "eth_type": eth_type,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "tcp_flags": tcp_flags,
                }
                with self.lock:
                    self.packets.append(rec)
            except socket.timeout:
                continue
            except Exception:
                continue
        sock.close()

    def start(self):
        self.stop_event.clear()
        for iface in self.interfaces:
            t = threading.Thread(target=self._sniff_interface, args=(iface,), daemon=True)
            t.start()
            self.threads.append(t)
        logger.info("PacketTelemetrySniffer active on interfaces: %s", self.interfaces)

    def stop(self) -> List[Dict[str, Any]]:
        self.stop_event.set()
        for t in self.threads:
            t.join(timeout=2.0)
        logger.info("Sniffer stopped. Total captured packets: %d", len(self.packets))
        return self.packets


def run_mininet_experiments():
    logger.info("=" * 80)
    logger.info("TASK 18: MININET UNSEEN CAPTURE EXPERIMENT RUNNER")
    logger.info("=" * 80)

    if not _MININET_OK:
        raise RuntimeError("Mininet is not installed or importable!")

    mininet_cleanup()

    logger.info("Building 5-host star topology (s1 + h1..h5)...")
    net = Mininet(switch=OVSSwitch, autoSetMacs=True)
    s1 = net.addSwitch("s1", failMode="standalone")
    hosts = {}
    for i in range(1, 6):
        hid = f"h{i}"
        ip = f"10.0.0.{i}"
        hosts[hid] = net.addHost(hid, ip=ip)
        net.addLink(hosts[hid], s1)

    net.start()
    logger.info("Mininet network started successfully!")

    # Switch interfaces for N=5 hosts are s1-eth1 through s1-eth5
    switch_ifaces = [f"s1-eth{i}" for i in range(1, 6)]
    sniffer = PacketTelemetrySniffer(switch_ifaces)
    sniffer.start()

    h1, h2, h3, h4, h5 = hosts["h1"], hosts["h2"], hosts["h3"], hosts["h4"], hosts["h5"]

    # Start victim services on h2
    logger.info("Starting victim services on h2 (HTTP on port 80, iperf UDP on 5001)...")
    h2.cmd("python3 -m http.server 80 > /dev/null 2>&1 & echo $! > /tmp/h2_http.pid")
    h2.cmd("iperf -s -u -p 5001 > /dev/null 2>&1 & echo $! > /tmp/h2_iperf_u.pid")
    h2.cmd("iperf -s -p 5002 > /dev/null 2>&1 & echo $! > /tmp/h2_iperf_t.pid")
    time.sleep(2)

    # Initial ping check
    loss = net.pingAll(timeout="1")
    logger.info("Initial topology ping connectivity test loss: %.1f%%", loss)

    schedule_events = []

    # ─── 8 Controlled Experiment Sessions ─────────────────────────────────────
    # Host roles:
    # h1: Attacker
    # h2: Victim Server
    # h3, h4, h5: Legitimate Clients

    sessions_config = [
        {
            "session_id": "session_01_benign_light",
            "description": "Benign baseline HTTP requests and periodic ping traffic",
            "duration": 16,
            "attack_type": None,
        },
        {
            "session_id": "session_02_syn_flood",
            "description": "Controlled TCP SYN Flood attack against h2:80",
            "baseline_sec": 6,
            "attack_sec": 12,
            "recovery_sec": 6,
            "attack_type": "SYN_FLOOD",
        },
        {
            "session_id": "session_03_udp_flood",
            "description": "High-bandwidth UDP flood against h2:5001",
            "baseline_sec": 6,
            "attack_sec": 12,
            "recovery_sec": 6,
            "attack_type": "UDP_FLOOD",
        },
        {
            "session_id": "session_04_icmp_flood",
            "description": "High-rate ICMP ping flood against h2",
            "baseline_sec": 6,
            "attack_sec": 12,
            "recovery_sec": 6,
            "attack_type": "ICMP_FLOOD",
        },
        {
            "session_id": "session_05_benign_bursty",
            "description": "Benign bursty traffic: large HTTP transfers and multi-host ping",
            "duration": 18,
            "attack_type": None,
        },
        {
            "session_id": "session_06_port_scan_probe",
            "description": "Port Scan PROBE: TCP SYN sweep across destination ports 20-100",
            "baseline_sec": 6,
            "attack_sec": 14,
            "recovery_sec": 6,
            "attack_type": "PROBE",
        },
        {
            "session_id": "session_07_unseen_multivector_test",
            "description": "Multi-vector test: Port Scan followed by targeted SYN flood burst",
            "baseline_sec": 6,
            "attack_phase1_sec": 10,
            "attack_type_1": "PROBE",
            "attack_phase2_sec": 10,
            "attack_type_2": "SYN_FLOOD",
            "recovery_sec": 6,
            "attack_type": "MULTIVECTOR",
        },
        {
            "session_id": "session_08_unseen_eval_scenario",
            "description": "Final evaluation scenario: UDP flood burst and wide port sweep",
            "baseline_sec": 6,
            "attack_phase1_sec": 10,
            "attack_type_1": "UDP_FLOOD",
            "attack_phase2_sec": 10,
            "attack_type_2": "PROBE",
            "recovery_sec": 6,
            "attack_type": "MULTIVECTOR",
        },
    ]

    for sc in sessions_config:
        sid = sc["session_id"]
        logger.info("\n>>> Starting Session: %s — %s", sid, sc["description"])
        t_sess_start = time.time()
        active_attacks = []

        if sc["attack_type"] is None:
            # Benign session: continuous legitimate requests
            t_end = t_sess_start + sc["duration"]
            while time.time() < t_end:
                h3.cmd("curl -s -m 1 http://10.0.0.2:80/ > /dev/null &")
                h4.cmd("ping -c 2 -W 1 10.0.0.2 > /dev/null &")
                h5.cmd("curl -s -m 1 http://10.0.0.2:80/ > /dev/null &")
                time.sleep(1.5)
        elif sc["attack_type"] in ("SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "PROBE"):
            # Single attack session: Baseline -> Attack -> Recovery
            t_base_end = time.time() + sc["baseline_sec"]
            logger.info("  [Baseline Phase] %ds...", sc["baseline_sec"])
            while time.time() < t_base_end:
                h3.cmd("curl -s -m 1 http://10.0.0.2:80/ > /dev/null &")
                h4.cmd("ping -c 1 -W 1 10.0.0.2 > /dev/null &")
                time.sleep(1.5)

            t_atk_start = time.time()
            logger.info("  [ATTACK Phase] %s for %ds...", sc["attack_type"], sc["attack_sec"])
            atk_cmd = ""
            if sc["attack_type"] == "SYN_FLOOD":
                atk_cmd = "hping3 -S -p 80 -i u1000 10.0.0.2 > /dev/null 2>&1 &"
                h1.cmd(atk_cmd)
            elif sc["attack_type"] == "UDP_FLOOD":
                atk_cmd = "iperf -c 10.0.0.2 -u -b 20M -t 20 > /dev/null 2>&1 &"
                h1.cmd(atk_cmd)
            elif sc["attack_type"] == "ICMP_FLOOD":
                atk_cmd = "hping3 --icmp -i u1000 10.0.0.2 > /dev/null 2>&1 &"
                h1.cmd(atk_cmd)
            elif sc["attack_type"] == "PROBE":
                # TCP SYN Port sweep across ports 20-100
                atk_cmd = "hping3 --scan 20-100 -S 10.0.0.2 > /dev/null 2>&1 &"
                h1.cmd(atk_cmd)

            # Concurrent legitimate background traffic during attack
            t_atk_end = t_atk_start + sc["attack_sec"]
            while time.time() < t_atk_end:
                h3.cmd("curl -s -m 1 http://10.0.0.2:80/ > /dev/null &")
                h5.cmd("ping -c 1 -W 1 10.0.0.2 > /dev/null &")
                time.sleep(1.0)

            # Terminate attack process on h1
            h1.cmd("killall -9 hping3 iperf > /dev/null 2>&1")
            actual_atk_end = time.time()
            active_attacks.append({
                "attack_type": sc["attack_type"],
                "start_time": t_atk_start,
                "end_time": actual_atk_end,
                "attacker": "h1 (10.0.0.1)",
                "target": "h2 (10.0.0.2)",
                "command": atk_cmd
            })

            logger.info("  [Recovery Phase] %ds...", sc["recovery_sec"])
            t_rec_end = time.time() + sc["recovery_sec"]
            while time.time() < t_rec_end:
                h4.cmd("ping -c 1 -W 1 10.0.0.2 > /dev/null &")
                time.sleep(1.5)
        elif sc["attack_type"] == "MULTIVECTOR":
            # Multi-vector session: Baseline -> Phase 1 -> Phase 2 -> Recovery
            t_base_end = time.time() + sc["baseline_sec"]
            while time.time() < t_base_end:
                h3.cmd("curl -s -m 1 http://10.0.0.2:80/ > /dev/null &")
                h4.cmd("ping -c 1 -W 1 10.0.0.2 > /dev/null &")
                time.sleep(1.5)

            # Phase 1
            t_p1_start = time.time()
            a1_type = sc["attack_type_1"]
            logger.info("  [ATTACK Phase 1] %s for %ds...", a1_type, sc["attack_phase1_sec"])
            cmd1 = ""
            if a1_type == "PROBE":
                cmd1 = "hping3 --scan 20-80 -S 10.0.0.2 > /dev/null 2>&1 &"
                h1.cmd(cmd1)
            elif a1_type == "UDP_FLOOD":
                cmd1 = "iperf -c 10.0.0.2 -u -b 15M -t 15 > /dev/null 2>&1 &"
                h1.cmd(cmd1)

            t_p1_end = t_p1_start + sc["attack_phase1_sec"]
            while time.time() < t_p1_end:
                h5.cmd("curl -s -m 1 http://10.0.0.2:80/ > /dev/null &")
                time.sleep(1.0)
            h1.cmd("killall -9 hping3 iperf > /dev/null 2>&1")
            active_attacks.append({
                "attack_type": a1_type,
                "start_time": t_p1_start,
                "end_time": time.time(),
                "attacker": "h1 (10.0.0.1)",
                "target": "h2 (10.0.0.2)",
                "command": cmd1
            })

            # Phase 2
            t_p2_start = time.time()
            a2_type = sc["attack_type_2"]
            logger.info("  [ATTACK Phase 2] %s for %ds...", a2_type, sc["attack_phase2_sec"])
            cmd2 = ""
            if a2_type == "SYN_FLOOD":
                cmd2 = "hping3 -S -p 80 -i u1500 10.0.0.2 > /dev/null 2>&1 &"
                h1.cmd(cmd2)
            elif a2_type == "PROBE":
                cmd2 = "hping3 --scan 80-150 -S 10.0.0.2 > /dev/null 2>&1 &"
                h1.cmd(cmd2)

            t_p2_end = t_p2_start + sc["attack_phase2_sec"]
            while time.time() < t_p2_end:
                h3.cmd("ping -c 1 -W 1 10.0.0.2 > /dev/null &")
                time.sleep(1.0)
            h1.cmd("killall -9 hping3 iperf > /dev/null 2>&1")
            active_attacks.append({
                "attack_type": a2_type,
                "start_time": t_p2_start,
                "end_time": time.time(),
                "attacker": "h1 (10.0.0.1)",
                "target": "h2 (10.0.0.2)",
                "command": cmd2
            })

            logger.info("  [Recovery Phase] %ds...", sc["recovery_sec"])
            t_rec_end = time.time() + sc["recovery_sec"]
            while time.time() < t_rec_end:
                h4.cmd("curl -s -m 1 http://10.0.0.2:80/ > /dev/null &")
                time.sleep(1.5)

        t_sess_end = time.time()
        logger.info("Completed %s (duration: %.2fs)", sid, t_sess_end - t_sess_start)

        schedule_events.append({
            "session_id": sid,
            "description": sc["description"],
            "session_start": t_sess_start,
            "session_end": t_sess_end,
            "active_attacks": active_attacks,
        })
        time.sleep(2)

    # Teardown
    logger.info("Stopping victim processes and Mininet...")
    h2.cmd("kill -9 $(cat /tmp/h2_http.pid 2>/dev/null) 2>/dev/null")
    h2.cmd("kill -9 $(cat /tmp/h2_iperf_u.pid 2>/dev/null) 2>/dev/null")
    h2.cmd("kill -9 $(cat /tmp/h2_iperf_t.pid 2>/dev/null) 2>/dev/null")
    h2.cmd("killall -9 iperf > /dev/null 2>&1")
    h1.cmd("killall -9 hping3 iperf > /dev/null 2>&1")
    captured_packets = sniffer.stop()
    net.stop()
    mininet_cleanup()

    # Save experiment schedule
    schedule_manifest = {
        "timestamp": datetime.now().isoformat(),
        "topology": "IntelliShieldTopo (1 switch, 5 hosts)",
        "hosts": {
            "h1": {"ip": "10.0.0.1", "role": "attacker"},
            "h2": {"ip": "10.0.0.2", "role": "victim_server (HTTP:80, iperf:5001/5002)"},
            "h3": {"ip": "10.0.0.3", "role": "legitimate_client"},
            "h4": {"ip": "10.0.0.4", "role": "legitimate_client"},
            "h5": {"ip": "10.0.0.5", "role": "legitimate_client"},
        },
        "total_sessions": len(schedule_events),
        "sessions": schedule_events,
        "total_raw_packets_captured": len(captured_packets),
    }

    with open(SCHEDULE_JSON, "w") as f:
        json.dump(schedule_manifest, f, indent=2)
    logger.info("Saved experiment schedule: %s", SCHEDULE_JSON)

    # Save raw packet stream CSV using built-in csv module (zero dependency on pandas)
    logger.info("Flushing %d raw packets to %s...", len(captured_packets), RAW_PACKETS_CSV)
    import csv
    if captured_packets:
        fieldnames = list(captured_packets[0].keys())
        with open(RAW_PACKETS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(captured_packets)
    logger.info("Saved raw packet stream: %s (size: %d bytes)", RAW_PACKETS_CSV, os.path.getsize(RAW_PACKETS_CSV))

    print("\n[OK] Task 18 Mininet Experiment Run Finished Successfully.")


if __name__ == "__main__":
    run_mininet_experiments()
