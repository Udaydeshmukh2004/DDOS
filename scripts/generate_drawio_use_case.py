#!/usr/bin/env python3
"""
Generate Draw.io (.drawio XML) and companion High-Res PNG/SVG for IntelliShield SDN Use Case Diagram.
Follows standard UML Use Case modeling:
  - System Boundary: IntelliShield-SDN System Boundary
  - Actors: Security Analyst / SOC Operator, Network Administrator
  - 11 Use Cases with authentic SDN engineering capabilities (No Login/Logout)
Outputs:
  - docs/architecture/intellishield_use_case_diagram.drawio
  - docs/architecture/intellishield_use_case_diagram.png (300 DPI)
  - docs/architecture/intellishield_use_case_diagram.svg
  - Desktop copies for direct 1-click access
"""

import os
import shutil
import xml.etree.ElementTree as ET
import matplotlib.pyplot as plt
import matplotlib.patches as patches

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS_DIR = os.path.join(ROOT, "docs", "architecture")
STATIC_DIR = os.path.join(ROOT, "dashboard", "static")
os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

DRAWIO_PATH = os.path.join(DOCS_DIR, "intellishield_use_case_diagram.drawio")
PNG_PATH = os.path.join(DOCS_DIR, "intellishield_use_case_diagram.png")
SVG_PATH = os.path.join(DOCS_DIR, "intellishield_use_case_diagram.svg")

DESKTOP_DIR = "/mnt/c/Users/deshm/OneDrive/Desktop"
BRAIN_DIR = "/mnt/c/Users/deshm/.gemini/antigravity/brain/f4598107-5979-4f10-b0aa-450d9f55e8db"


def generate_drawio_file():
    """Build valid draw.io XML document matching mxGraph model specification."""
    use_cases = [
        ("uc_1", "Monitor Network Traffic & Flow Statistics", 140),
        ("uc_2", "Analyze Shannon Traffic Entropy", 230),
        ("uc_3", "Detect DDoS Attacks via ML & SSL Autoencoder", 320),
        ("uc_4", "Correlate & Fuse Cross-Layer Signals", 410),
        ("uc_5", "Verify Suspicious Traffic (Multi-Stage Verification)", 500),
        ("uc_6", "View Real-Time SOC Dashboard & Analytics", 590),
        ("uc_7", "View XAI Explanations & Root Cause Reports", 680),
        ("uc_8", "Review Quarantined & Blocked Flows", 770),
        ("uc_9", "Apply & Enforce OpenFlow Mitigation Rules", 860),
        ("uc_10", "Configure Monitoring & Drift Thresholds", 950),
        ("uc_11", "Export Security Alerts & Audit Logs", 1040),
    ]

    analyst_links = ["uc_1", "uc_2", "uc_3", "uc_4", "uc_5", "uc_6", "uc_11"]
    admin_links = ["uc_1", "uc_6", "uc_7", "uc_8", "uc_9", "uc_10", "uc_11"]

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<mxfile host="app.diagrams.net" modified="2026-10-27T10:00:00.000Z" agent="IntelliShield SDN" version="22.1.0" type="device">',
        '  <diagram id="intellishield_usecase" name="IntelliShield-SDN Use Case Diagram">',
        '    <mxGraphModel dx="1422" dy="1200" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1280" pageHeight="1300" background="#FFFFFF" math="0" shadow="0">',
        '      <root>',
        '        <mxCell id="0" />',
        '        <mxCell id="1" parent="0" />',
        '',
        '        <!-- System Boundary Box -->',
        '        <mxCell id="boundary" value="IntelliShield-SDN System Boundary" style="shape=swimlane;whiteSpace=wrap;html=1;startSize=32;swimlaneFillColor=#FFFFFF;strokeColor=#1E293B;strokeWidth=2;fontStyle=1;fontSize=14;fontColor=#1E293B;fillColor=#FFFFFF;collapsible=0;rounded=1;arcSize=4;" vertex="1" parent="1">',
        '          <mxGeometry x="280" y="70" width="680" height="1100" as="geometry" />',
        '        </mxCell>',
        '',
        '        <!-- Left Actor: Security Analyst / SOC Operator -->',
        '        <mxCell id="actor_analyst" value="Security Analyst /&#xa;SOC Operator" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;outlineConnect=0;strokeColor=#1E293B;strokeWidth=2;fillColor=#F8FAFC;fontStyle=1;fontSize=13;fontColor=#0F172A;" vertex="1" parent="1">',
        '          <mxGeometry x="90" y="550" width="70" height="140" as="geometry" />',
        '        </mxCell>',
        '',
        '        <!-- Right Actor: Network Administrator -->',
        '        <mxCell id="actor_admin" value="Network&#xa;Administrator" style="shape=umlActor;verticalLabelPosition=bottom;verticalAlign=top;html=1;outlineConnect=0;strokeColor=#1E293B;strokeWidth=2;fillColor=#F8FAFC;fontStyle=1;fontSize=13;fontColor=#0F172A;" vertex="1" parent="1">',
        '          <mxGeometry x="1100" y="550" width="70" height="140" as="geometry" />',
        '        </mxCell>',
        '',
        '        <!-- Use Case Ellipses -->',
    ]

    for ucid, text, ypos in use_cases:
        lines.append(
            f'        <mxCell id="{ucid}" value="{text}" style="ellipse;whiteSpace=wrap;html=1;strokeColor=#1E293B;strokeWidth=2;fillColor=#FFFFFF;fontStyle=1;fontSize=12;fontColor=#0F172A;shadow=0;" vertex="1" parent="boundary">'
        )
        lines.append(f'          <mxGeometry x="90" y="{ypos}" width="500" height="58" as="geometry" />')
        lines.append('        </mxCell>')

    lines.append('')
    lines.append('        <!-- Actor Connection Lines (Analyst) -->')
    for ucid in analyst_links:
        edge_id = f"edge_analyst_{ucid}"
        lines.append(
            f'        <mxCell id="{edge_id}" style="endArrow=none;html=1;strokeColor=#1E293B;strokeWidth=1.8;entryX=0;entryY=0.5;entryDx=0;entryDy=0;exitX=1;exitY=0.33;exitDx=0;exitDy=0;exitPerimeter=0;" edge="1" parent="1" source="actor_analyst" target="{ucid}">'
        )
        lines.append('          <mxGeometry relative="1" as="geometry" />')
        lines.append('        </mxCell>')

    lines.append('')
    lines.append('        <!-- Actor Connection Lines (Admin) -->')
    for ucid in admin_links:
        edge_id = f"edge_admin_{ucid}"
        lines.append(
            f'        <mxCell id="{edge_id}" style="endArrow=none;html=1;strokeColor=#1E293B;strokeWidth=1.8;entryX=1;entryY=0.5;entryDx=0;entryDy=0;exitX=0;exitY=0.33;exitDx=0;exitDy=0;exitPerimeter=0;" edge="1" parent="1" source="actor_admin" target="{ucid}">'
        )
        lines.append('          <mxGeometry relative="1" as="geometry" />')
        lines.append('        </mxCell>')

    lines.append('      </root>')
    lines.append('    </mxGraphModel>')
    lines.append('  </diagram>')
    lines.append('</mxfile>')

    with open(DRAWIO_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Generated Draw.io: {DRAWIO_PATH}")


def generate_png_and_svg():
    """Generate high-resolution PNG (300 DPI) and SVG matching the Draw.io layout."""
    fig_w, fig_h = 12.8, 15.0
    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    ax.axis("off")
    ax.set_xlim(0, fig_w)
    ax.set_ylim(0, fig_h)

    # Boundary
    bx, by, bw, bh = 2.8, 0.8, 6.8, 13.2
    boundary = patches.Rectangle((bx, by), bw, bh, facecolor="#ffffff", edgecolor="#1e293b", linewidth=1.8, zorder=2)
    ax.add_patch(boundary)

    # Title header tab
    tab_w, tab_h = 3.2, 0.45
    tab = patches.Rectangle((bx, by + bh - tab_h), tab_w, tab_h, facecolor="#f1f5f9", edgecolor="#1e293b", linewidth=1.5, zorder=3)
    ax.add_patch(tab)
    ax.text(bx + tab_w / 2, by + bh - tab_h / 2, "IntelliShield-SDN Boundary", ha="center", va="center", fontsize=10.5, fontweight="bold", color="#0f172a", zorder=4)

    # Use Cases
    use_cases = [
        "Monitor Network Traffic & Flow Statistics",
        "Analyze Shannon Traffic Entropy",
        "Detect DDoS Attacks via ML & SSL Autoencoder",
        "Correlate & Fuse Cross-Layer Signals",
        "Verify Suspicious Traffic (Multi-Stage Verification)",
        "View Real-Time SOC Dashboard & Analytics",
        "View XAI Explanations & Root Cause Reports",
        "Review Quarantined & Blocked Flows",
        "Apply & Enforce OpenFlow Mitigation Rules",
        "Configure Monitoring & Drift Thresholds",
        "Export Security Alerts & Audit Logs",
    ]

    n = len(use_cases)
    y_start = by + bh - 1.05
    y_end = by + 0.85
    y_step = (y_start - y_end) / (n - 1)
    cx = bx + bw / 2
    ow, oh = 5.2, 0.68

    uc_pts = []
    for i, text in enumerate(use_cases):
        cy = y_start - i * y_step
        uc_pts.append((cx, cy))
        el = patches.Ellipse((cx, cy), ow, oh, facecolor="#ffffff", edgecolor="#1e293b", linewidth=1.5, zorder=4)
        ax.add_patch(el)
        ax.text(cx, cy, text, ha="center", va="center", fontsize=9.2, fontweight="bold", color="#0f172a", zorder=5)

    def draw_actor(x, y, label):
        scale = 1.1
        # Head
        ax.add_patch(patches.Circle((x, y + 0.85 * scale), 0.22 * scale, facecolor="white", edgecolor="#1e293b", linewidth=1.8, zorder=6))
        # Torso
        ax.plot([x, x], [y + 0.85 * scale - 0.22 * scale, y + 0.15 * scale], color="#1e293b", linewidth=2.0, zorder=6)
        # Arms
        ax.plot([x - 0.38 * scale, x, x + 0.38 * scale], [y + 0.40 * scale, y + 0.55 * scale, y + 0.40 * scale], color="#1e293b", linewidth=2.0, zorder=6)
        # Legs
        ax.plot([x - 0.32 * scale, x, x + 0.32 * scale], [y - 0.50 * scale, y + 0.15 * scale, y - 0.50 * scale], color="#1e293b", linewidth=2.0, zorder=6)
        # Label
        ax.text(x, y - 0.85 * scale, label, ha="center", va="top", fontsize=11.5, fontweight="bold", color="#0f172a", zorder=6)

    # Left Actor
    ax_left, ay_left = 1.35, by + bh * 0.50
    draw_actor(ax_left, ay_left, "Security Analyst /\nSOC Operator")

    # Right Actor
    ax_right, ay_right = 11.25, by + bh * 0.50
    draw_actor(ax_right, ay_right, "Network\nAdministrator")

    # Connector lines
    left_hand = (ax_left + 0.42, ay_left + 0.45)
    right_hand = (ax_right - 0.42, ay_right + 0.45)

    analyst_idx = [0, 1, 2, 3, 4, 5, 10]
    admin_idx = [0, 5, 6, 7, 8, 9, 10]

    for idx in analyst_idx:
        px, py = uc_pts[idx]
        ax.plot([left_hand[0], px - ow / 2 + 0.08], [left_hand[1], py], color="#1e293b", linewidth=1.4, zorder=3)

    for idx in admin_idx:
        px, py = uc_pts[idx]
        ax.plot([right_hand[0], px + ow / 2 - 0.08], [right_hand[1], py], color="#1e293b", linewidth=1.4, zorder=3)

    plt.tight_layout()
    plt.savefig(PNG_PATH, dpi=300, bbox_inches="tight", facecolor="white")
    plt.savefig(SVG_PATH, format="svg", bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"Generated PNG: {PNG_PATH}")
    print(f"Generated SVG: {SVG_PATH}")


def copy_to_destinations():
    # Copy to static web
    for src, name in [(DRAWIO_PATH, "intellishield_use_case_diagram.drawio"),
                      (PNG_PATH, "intellishield_use_case_diagram.png"),
                      (SVG_PATH, "intellishield_use_case_diagram.svg")]:
        try:
            shutil.copyfile(src, os.path.join(STATIC_DIR, name))
        except Exception as e:
            print(f"Static copy warning: {e}")

    # Copy to Desktop
    if os.path.isdir(DESKTOP_DIR):
        for src, name in [(DRAWIO_PATH, "intellishield_use_case_diagram.drawio"),
                          (PNG_PATH, "intellishield_use_case_diagram.png"),
                          (SVG_PATH, "intellishield_use_case_diagram.svg")]:
            try:
                dst = os.path.join(DESKTOP_DIR, name)
                shutil.copyfile(src, dst)
                print(f"Copied to Desktop: {dst}")
            except Exception as e:
                print(f"Desktop copy warning: {e}")

    # Copy to Brain Artifact dir
    if os.path.isdir(BRAIN_DIR):
        for src, name in [(DRAWIO_PATH, "intellishield_use_case_diagram.drawio"),
                          (PNG_PATH, "intellishield_use_case_diagram.png"),
                          (SVG_PATH, "intellishield_use_case_diagram.svg")]:
            try:
                dst = os.path.join(BRAIN_DIR, name)
                shutil.copyfile(src, dst)
                print(f"Copied to Brain Artifacts: {dst}")
            except Exception as e:
                print(f"Brain copy warning: {e}")


if __name__ == "__main__":
    generate_drawio_file()
    generate_png_and_svg()
    copy_to_destinations()

