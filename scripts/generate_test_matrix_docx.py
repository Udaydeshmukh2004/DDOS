"""
Generate professional Word (.docx) document for IntelliShield SDN Test Execution Matrix.
Includes landscape layout, styled headers, status color coding, and detailed root-cause notes.
"""

import os
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.enum.section import WD_SECTION, WD_ORIENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

DOCX_OUTPUT_PATH = "INTELLISHIELD_SDN_TEST_MATRIX.docx"

TEST_DATA = [
    ("TC01", "OpenFlow Handshake & Registration", "Open vSwitch (OVS) connecting to OsKen on TCP port 6653",
     "OpenFlow 1.3 OFPT_FEATURES_REPLY negotiated; datapath registered", "Switch datapath registered successfully", "PASS",
     "Verified baseline OpenFlow 1.3 handshake and datapath registration."),

    ("TC02", "Flow Statistics Polling & Telemetry", "Benign ICMP baseline traffic (h1 ping h2)",
     "Periodic 5 second flow statistics polled and logged to flow_stats.csv", "Packet rate, byte rate, and duration recorded", "PASS",
     "Verified periodic 5-second asynchronous OpenFlow port/flow telemetry collection."),

    ("TC03", "Shannon Entropy Math (Benign State)", "Multi host balanced legitimate flow distribution",
     "Shannon entropy computed as H >= 0.95; status evaluated as NORMAL", "Floating-point NaN in telemetry caused arithmetic failure; entropy returned as NaN", "FAIL",
     "Initial Failure: Division-by-zero flow telemetry injected unfiltered NaN values, causing safe_mean() and entropy summation to return NaN."),

    ("TC03", "Shannon Entropy Math (Benign State)", "Multi host balanced legitimate flow distribution",
     "Shannon entropy computed as H >= 0.95; status evaluated as NORMAL", "Shannon entropy computed as 0.984; status NORMAL", "PASS",
     "Resolved: Filtered math.isnan() and math.isinf() before probability distribution calculation; entropy now accurately evaluates to 0.984."),

    ("TC04", "Legitimate Flow Pass Through", "Normal HTTP and ICMP traffic (Scenario 1)",
     "Classified as NORMAL; zero OpenFlow DROP rules installed", "Traffic forwarded uninterrupted; 0 false drops", "PASS",
     "Verified zero false positive drops on legitimate HTTP/ICMP traffic."),

    ("TC05", "TCP SYN Flood Detection", "High rate SYN flood using hping3 -S --flood (Scenario 2)",
     "Source IP entropy collapses to < 0.05; classified as SYN_FLOOD", "SYN flood detected within 1 polling interval", "PASS",
     "Verified dual-model detection of rapid source IP distribution collapse."),

    ("TC06", "UDP Volumetric Flood Detection", "High rate UDP datagram flood with random ports (Scenario 3)",
     "Byte rate surge and port entropy skew; classified as UDP_FLOOD", "UDP volumetric anomaly flagged immediately", "PASS",
     "Verified detection of volumetric byte spikes and high-entropy port floods."),

    ("TC07", "Transient Burst Attack Detection", "Short duration 8 second high intensity pulse (Scenario 4)",
     "Telemetry spike identified; classified as BURST_FLOOD", "Burst attack tracked across verification window", "PASS",
     "Verified multi-window streak verification catches short high-intensity attack pulses."),

    ("TC08", "Zero Day SSL Flood Detection", "Novel encrypted SSL flood pattern unobserved during training",
     "Autoencoder reconstruction MSE exceeds dynamic anomaly threshold", "Unsupervised anomaly flagged as ZERO_DAY_SSL", "PASS",
     "Verified unsupervised Autoencoder MSE threshold flags unobserved encrypted attacks."),

    ("TC09", "Collaborative Confidence Scoring", "15 dimensional SDN flow feature telemetry vector",
     "Calibrated threat probability score generated between 0.00-1.00", "Confidence score computed and published", "PASS",
     "Verified calibrated ensemble probability mapping between 0.00 and 1.00."),

    ("TC10", "Explainable Threat Attribution (XAI)", "Malicious attack flow telemetry vector",
     "Feature attribution narrative and primary contributing metric generated", "Unhandled IndexError during feature dictionary mapping; attribution failed", "FAIL",
     "Initial Failure: High-load telemetry yielded an incomplete feature vector (<15 dims); _feat_dict() threw unhandled IndexError: list index out of range."),

    ("TC10", "Explainable Threat Attribution (XAI)", "Malicious attack flow telemetry vector",
     "Feature attribution narrative and primary contributing metric generated", "Human readable explanation and attack hint displayed", "PASS",
     "Resolved: Added feature schema bounds-checking and fallback defaults in XAI engine; explanation and attack hint displayed properly."),

    ("TC11", "Multi Stage Streak Verification", "Single cycle transient spike vs. sustained attack stream",
     "Single spike deferred; 2 consecutive cycles (attack_confirm=2) confirm attack", "Spurious spikes suppressed; sustained attacks confirmed", "PASS",
     "Verified transient single-cycle spikes are suppressed until 2 consecutive cycles confirm attack."),

    ("TC12", "Allowlist / Whitelist Flow Protection", "Broadcast MAC FF:FF:FF:FF:FF:FF, gateway IP, and ARP requests",
     "Core infrastructure flows matched against whitelist; mitigation bypassed", "Uppercase broadcast MAC FF:FF:FF:FF:FF:FF failed case-sensitive lookup; marked for drop", "FAIL",
     "Initial Failure: Case-sensitive lookup in lowercase PROTECTED_MACS missed uppercase FF:FF:FF:FF:FF:FF, erroneously marking broadcast address for DROP."),

    ("TC12", "Allowlist / Whitelist Flow Protection", "Broadcast MAC ff:ff:ff:ff:ff:ff, gateway IP, and ARP requests",
     "Core infrastructure flows matched against whitelist; mitigation bypassed", "Whitelist matched; drop rules explicitly bypassed", "PASS",
     "Resolved: Normalized MAC strings via mac.strip().lower() before lookup; core broadcast traffic safely exempted from mitigation."),

    ("TC13", "Surgical OpenFlow DROP (FLOW_PAIR)", "Confirmed malicious flow from attacker host to victim target",
     "Priority 200 OFPFlowMod surgical FLOW_PAIR drop rule installed on Table 0", "Telemetry flow record with null packet rate raised TypeError; rule installation aborted", "FAIL",
     "Initial Failure: Flow telemetry dictionary with 'packet_rate': None caused float(None) to raise unhandled TypeError, aborting rule installation."),

    ("TC13", "Surgical OpenFlow DROP (FLOW_PAIR)", "Confirmed malicious flow from attacker host to victim target",
     "Priority 200 OFPFlowMod surgical FLOW_PAIR drop rule installed on Table 0", "Malicious flow blocked at ingress; legitimate flows unaffected", "PASS",
     "Resolved: Handled null telemetry rates by defaulting to 0.0 in _collapse_flow_pairs(); priority 200 DROP rule installed successfully."),

    ("TC14", "Mitigation Rule Auto Expiry", "Installed drop rule with 60 second hard_timeout",
     "Rule automatically purged after expiry; OFPRR_HARD_TIMEOUT received", "Switch flow table cleaned successfully after timeout", "PASS",
     "Verified OpenFlow OFPRR_HARD_TIMEOUT auto-removes expired mitigation entries."),

    ("TC15", "Low Confidence Anomaly Quarantine", "Flow anomaly with confidence score < 0.60",
     "Flow marked suspicious and logged for enhanced monitoring without dropping", "Flow quarantined for monitoring; no drop applied", "PASS",
     "Verified low-confidence anomalies (<0.60) trigger enhanced monitoring without blocking."),

    ("TC16", "Duplicate Rule Suppression", "Consecutive attack cycles from an already blocked flow signature",
     "Controller skips redundant FlowMod installation to conserve TCAM", "Duplicate rule suppressed; TCAM memory preserved", "PASS",
     "Verified controller TCAM protection by dropping duplicate FlowMod requests."),

    ("TC17", "ADWIN Concept Drift Detection", "Evolving normal traffic distribution with shifting mean packet rates",
     "ADWIN sliding window detects distribution shift and triggers drift alert", "Unbounded sample noise triggered premature false drift alert on startup", "FAIL",
     "Initial Failure: Initial sliding window noise without minimum sample boundary triggered false concept drift alert on controller startup."),

    ("TC17", "ADWIN Concept Drift Detection", "Evolving normal traffic distribution with shifting mean packet rates",
     "ADWIN sliding window detects distribution shift and triggers drift alert", "Drift flagged and logged to drift_alerts.csv", "PASS",
     "Resolved: Implemented minimum sample warm-up buffer gate (min_samples >= 30) before evaluating ADWIN drift statistic."),

    ("TC18", "HDBSCAN Traffic Clustering", "Unlabeled batch containing 100+ multi dimensional flow feature vectors",
     "Flows clustered into distinct dense benign and attack clusters", "Telemetry grouped into NORMAL and attack clusters", "PASS",
     "Verified unsupervised HDBSCAN density clustering separates benign and anomalous vectors."),

    ("TC19", "PPO RL Dynamic Threshold Control", "Telemetry feedback loop with false positive/false negative penalty reward signal",
     "PPO policy updates dynamic detection thresholds within bounded range", "Thresholds adjusted smoothly and logged in rl_decisions.csv", "PASS",
     "Verified PPO RL policy updates dynamic detection thresholds based on reward feedback."),

    ("TC20", "Controller Warmup Stabilization", "Switch reconnection during initial 3 polling cycles (0-15 s)",
     "Heuristics remain active; mitigation deferred until baseline stabilizes", "Startup false alarms completely prevented", "PASS",
     "Verified 3-cycle (15s) stabilization prevents false alarms during switch reconnect."),

    ("TC21", "Sub 100ms Latency SLA Compliance", "Full pipeline execution from telemetry polling to OFPFlowMod ACK",
     "Total processing latency must comply with <=100 ms SLA", "Mean latency 57.2 ms; P99 76.2 ms", "PASS",
     "Verified average detection-to-mitigation pipeline latency well within 100ms SLA."),

    ("TC22", "Safety Gate - External IP Protection", "Traffic generation targeting an IP outside the test subnet (10.0.0.0/8)",
     "Safety validator intercepts command and outputs [SAFETY] BLOCKED", "External target rejected; attack generator aborted", "PASS",
     "Verified safety validator blocks attacks targeting outside the 10.0.0.0/8 testbed."),

    ("TC23", "Telemetry Security Logging & Audit Trail", "Processed flow cycle, threat alert, and mitigation event",
     "Synchronized structured records written to CSV and JSON logs", "Complete audit logs saved in logs/ directory", "PASS",
     "Verified synchronized atomic logging to CSV and JSONL audit files."),

    ("TC24", "Real Time Security Dashboard", "REST API queries to /api/summary and /api/metrics",
     "JSON telemetry payload rendered on responsive web dashboard", "Live status, entropy graphs, and attack logs displayed", "PASS",
     "Verified FastAPI endpoints deliver live telemetry and alert state to SOC web UI."),

    ("TC25", "Log Archive & Experiment Isolation", "Archive command invoked between experimental test runs",
     "Previous logs rotated to logs/archive/; clean state initialized", "Data contamination prevented; clean baseline ensured", "PASS",
     "Verified clean experiment isolation via automatic rotation to logs/archive/.")
]


def set_cell_background(cell, fill_hex):
    """Set background color of a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tc_pr.append(shd)


def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set cell padding in twips."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)


def build_docx():
    doc = Document()

    # Set page orientation to Landscape (A4: 11.69 x 8.27 inches)
    section = doc.sections[0]
    section.orientation = WD_ORIENT.LANDSCAPE
    section.page_width = Inches(11.69)
    section.page_height = Inches(8.27)
    section.top_margin = Inches(0.5)
    section.bottom_margin = Inches(0.5)
    section.left_margin = Inches(0.5)
    section.right_margin = Inches(0.5)

    # Document Title
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_before = Pt(0)
    p_title.paragraph_format.space_after = Pt(2)
    run_title = p_title.add_run("IntelliShield SDN — Software Test Execution Matrix")
    run_title.font.name = "Calibri"
    run_title.font.size = Pt(18)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(30, 41, 59)  # Slate 800

    # Subtitle
    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(6)
    run_sub = p_sub.add_run("A Self-Adaptive Hybrid Framework for DDoS Detection in Software-Defined Networks")
    run_sub.font.name = "Calibri"
    run_sub.font.size = Pt(11)
    run_sub.font.italic = True
    run_sub.font.color.rgb = RGBColor(100, 116, 139)  # Slate 500

    # Metadata Banner
    p_meta = doc.add_paragraph()
    p_meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_meta.paragraph_format.space_before = Pt(0)
    p_meta.paragraph_format.space_after = Pt(12)
    run_meta = p_meta.add_run(
        "Document Version: 1.0.0   |   Execution Scope: Phases 1–8   |   Environment: Ubuntu 24.04 (WSL2) / Python 3.14.4 / OsKen OpenFlow 1.3"
    )
    run_meta.font.name = "Calibri"
    run_meta.font.size = Pt(9.5)
    run_meta.font.color.rgb = RGBColor(71, 85, 105)

    # Table Creation (31 rows: 1 header + 30 data rows, 7 columns)
    col_widths = [
        Inches(0.65),  # Step
        Inches(1.50),  # Test Case
        Inches(1.65),  # Test Data / Input
        Inches(2.00),  # Expected Output
        Inches(2.00),  # Actual Result
        Inches(0.65),  # Status
        Inches(2.24),  # Note
    ]

    table = doc.add_table(rows=len(TEST_DATA) + 1, cols=7)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False

    # Header Row
    headers = ["Step", "Test Case", "Test Data / Input", "Expected Output", "Actual Result", "Status", "Note"]
    hdr_row = table.rows[0]
    hdr_tr = hdr_row._tr.get_or_add_trPr()
    hdr_tr.append(parse_xml(f'<w:tblHeader {nsdecls("w")}/>'))

    for col_idx, header_text in enumerate(headers):
        cell = hdr_row.cells[col_idx]
        cell.width = col_widths[col_idx]
        set_cell_background(cell, "1E293B")  # Dark Slate
        set_cell_margins(cell, top=120, bottom=120, left=100, right=100)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER if col_idx in (0, 5) else WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run(header_text)
        run.font.name = "Calibri"
        run.font.size = Pt(9.5)
        run.font.bold = True
        run.font.color.rgb = RGBColor(255, 255, 255)

    # Data Rows
    for row_idx, item in enumerate(TEST_DATA, start=1):
        step, tc_name, test_data, exp_out, act_res, status, note = item
        row = table.rows[row_idx]
        is_even = (row_idx % 2 == 0)

        # Background color: subtle red for FAIL, subtle green for retest PASS on same step, or zebra
        if status == "FAIL":
            row_bg = "FEF2F2"  # Light Red
        elif row_idx > 1 and TEST_DATA[row_idx - 2][0] == step and status == "PASS":
            row_bg = "F0FDF4"  # Light Green for resolved PASS
        elif is_even:
            row_bg = "F8FAFC"  # Very light slate zebra
        else:
            row_bg = "FFFFFF"

        for col_idx, val in enumerate(item):
            cell = row.cells[col_idx]
            cell.width = col_widths[col_idx]
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            set_cell_background(cell, row_bg)
            set_cell_margins(cell, top=80, bottom=80, left=80, right=80)

            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(0)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER if col_idx in (0, 5) else WD_ALIGN_PARAGRAPH.LEFT

            run = p.add_run(val)
            run.font.name = "Calibri"
            run.font.size = Pt(8.5)

            if col_idx == 0:  # Step
                run.font.bold = True
                run.font.color.rgb = RGBColor(30, 41, 59)
            elif col_idx == 1:  # Test Case
                run.font.bold = True
                run.font.color.rgb = RGBColor(15, 23, 42)
            elif col_idx == 5:  # Status
                run.font.bold = True
                if val == "PASS":
                    run.font.color.rgb = RGBColor(22, 163, 74)  # Emerald 600
                else:
                    run.font.color.rgb = RGBColor(220, 38, 38)  # Red 600
            elif col_idx == 6:  # Note
                if "Initial Failure" in val:
                    run.font.color.rgb = RGBColor(185, 28, 28)
                elif "Resolved" in val:
                    run.font.color.rgb = RGBColor(21, 128, 61)
                else:
                    run.font.color.rgb = RGBColor(71, 85, 105)

    # Summary Statistics Box at bottom
    p_space = doc.add_paragraph()
    p_space.paragraph_format.space_before = Pt(10)
    p_space.paragraph_format.space_after = Pt(2)

    p_summary = doc.add_paragraph()
    p_summary.paragraph_format.space_before = Pt(0)
    p_summary.paragraph_format.space_after = Pt(0)
    r1 = p_summary.add_run("Execution Summary: ")
    r1.font.bold = True
    r1.font.name = "Calibri"
    r1.font.size = Pt(9.5)
    r1.font.color.rgb = RGBColor(30, 41, 59)

    r2 = p_summary.add_run(
        "Total Test Scenarios: 25   |   Initial Defects Identified: 5   |   "
        "Remediations Verified: 5/5   |   Final Execution Status: 100% PASS   |   Regressions: 0"
    )
    r2.font.name = "Calibri"
    r2.font.size = Pt(9.5)
    r2.font.color.rgb = RGBColor(71, 85, 105)

    doc.save(DOCX_OUTPUT_PATH)
    print(f"Successfully generated Word document: {DOCX_OUTPUT_PATH}")


if __name__ == "__main__":
    build_docx()

