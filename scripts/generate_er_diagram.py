#!/usr/bin/env python3
"""
Generate publication-quality Entity-Relationship (ER) Diagram for IntelliShield SDN.
Follows classic Chen ER Diagram notation (Rectangles = Entities, Diamonds = Relationships,
Ellipses = Attributes) matching the style of the user reference image.
Outputs:
  - docs/architecture/intellishield_er_diagram.png (High-Res 300 DPI)
  - docs/architecture/intellishield_er_diagram.svg (Vector graphics)
  - Brain artifact directory copies for instant viewing
"""

import os
import math
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Polygon, Ellipse
import matplotlib.lines as mlines

# Output paths
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "docs", "architecture")
os.makedirs(OUT_DIR, exist_ok=True)
PNG_PATH = os.path.join(OUT_DIR, "intellishield_er_diagram.png")
SVG_PATH = os.path.join(OUT_DIR, "intellishield_er_diagram.svg")

# Also copy to brain artifact dir
BRAIN_DIR = r"C:\Users\deshm\.gemini\antigravity\brain\f4598107-5979-4f10-b0aa-450d9f55e8db"
BRAIN_PNG = os.path.join(BRAIN_DIR, "intellishield_er_diagram.png")
BRAIN_SVG = os.path.join(BRAIN_DIR, "intellishield_er_diagram.svg")


def create_er_diagram():
    fig, ax = plt.subplots(figsize=(26, 17), dpi=300)
    ax.set_xlim(0, 26)
    ax.set_ylim(0, 17)
    ax.set_aspect("equal")
    ax.axis("off")
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    # Styling constants matching reference
    BOX_BORDER_W = 2.0
    LINE_W = 1.6
    ATTR_LINE_W = 1.2
    TEXT_COLOR = "#0f172a"
    BOX_BG = "#ffffff"
    DIAMOND_BG = "#ffffff"
    ELLIPSE_BG = "#ffffff"

    FONT_FAMILY = "sans-serif"
    ENTITY_FONT_SIZE = 13.5
    REL_FONT_SIZE = 11.5
    ATTR_FONT_SIZE = 10.0
    CARD_FONT_SIZE = 12.0

    # ─────────────────────────────────────────────────────────────────────────────
    # Entity Definitions: (name, center_x, center_y, width, height)
    # ─────────────────────────────────────────────────────────────────────────────
    entities = {
        "Network_Node": {"cx": 3.8, "cy": 12.6, "w": 3.4, "h": 1.2},
        "Traffic_Flow": {"cx": 12.0, "cy": 12.6, "w": 3.4, "h": 1.2},
        "Detection_Event": {"cx": 20.2, "cy": 12.6, "w": 3.8, "h": 1.2},
        "Detection_Model": {"cx": 12.0, "cy": 7.4, "w": 4.0, "h": 1.2},
        "Correlation_Evidence": {"cx": 20.2, "cy": 7.4, "w": 4.2, "h": 1.2},
        "Mitigation_Action": {"cx": 17.0, "cy": 2.6, "w": 4.2, "h": 1.2},
        "Security_Log": {"cx": 6.8, "cy": 2.6, "w": 3.8, "h": 1.2},
    }

    # ─────────────────────────────────────────────────────────────────────────────
    # Relationship Definitions: (name, cx, cy, w, h)
    # ─────────────────────────────────────────────────────────────────────────────
    relationships = {
        "monitors": {"cx": 7.9, "cy": 12.6, "w": 2.2, "h": 1.2},
        "produces": {"cx": 16.1, "cy": 12.6, "w": 2.2, "h": 1.2},
        "analyzes": {"cx": 12.0, "cy": 10.0, "w": 2.2, "h": 1.2},
        "has": {"cx": 20.2, "cy": 10.0, "w": 1.8, "h": 1.1},
        "triggers": {"cx": 18.6, "cy": 5.4, "w": 2.2, "h": 1.2},
        "generates": {"cx": 11.9, "cy": 2.6, "w": 2.2, "h": 1.2},
        "receives": {"cx": 3.8, "cy": 6.8, "w": 2.2, "h": 1.2},
    }

    # ─────────────────────────────────────────────────────────────────────────────
    # Draw Lines & Connectors between Entities and Relationships
    # ─────────────────────────────────────────────────────────────────────────────
    def draw_line(p1, p2, lw=LINE_W):
        ax.plot([p1[0], p2[0]], [p1[1], p2[1]], color="#1e293b", lw=lw, zorder=2)

    def draw_cardinality(text, pos, offset=(0, 0)):
        ax.text(
            pos[0] + offset[0],
            pos[1] + offset[1],
            text,
            fontsize=CARD_FONT_SIZE,
            fontweight="normal",
            fontfamily=FONT_FAMILY,
            color=TEXT_COLOR,
            ha="center",
            va="center",
            zorder=6,
        )

    # 1. Network_Node -- monitors -- Traffic_Flow
    draw_line((entities["Network_Node"]["cx"] + entities["Network_Node"]["w"] / 2, 12.6), (relationships["monitors"]["cx"] - relationships["monitors"]["w"] / 2, 12.6))
    draw_line((relationships["monitors"]["cx"] + relationships["monitors"]["w"] / 2, 12.6), (entities["Traffic_Flow"]["cx"] - entities["Traffic_Flow"]["w"] / 2, 12.6))
    draw_cardinality("1", (5.8, 12.9))
    draw_cardinality("N", (10.0, 12.9))

    # 2. Traffic_Flow -- produces -- Detection_Event
    draw_line((entities["Traffic_Flow"]["cx"] + entities["Traffic_Flow"]["w"] / 2, 12.6), (relationships["produces"]["cx"] - relationships["produces"]["w"] / 2, 12.6))
    draw_line((relationships["produces"]["cx"] + relationships["produces"]["w"] / 2, 12.6), (entities["Detection_Event"]["cx"] - entities["Detection_Event"]["w"] / 2, 12.6))
    draw_cardinality("1", (14.0, 12.9))
    draw_cardinality("N", (18.0, 12.9))

    # 3. Traffic_Flow -- analyzes -- Detection_Model
    draw_line((12.0, entities["Traffic_Flow"]["cy"] - entities["Traffic_Flow"]["h"] / 2), (12.0, relationships["analyzes"]["cy"] + relationships["analyzes"]["h"] / 2))
    draw_line((12.0, relationships["analyzes"]["cy"] - relationships["analyzes"]["h"] / 2), (12.0, entities["Detection_Model"]["cy"] + entities["Detection_Model"]["h"] / 2))
    draw_cardinality("N", (12.3, 11.5))
    draw_cardinality("1", (12.3, 8.5))

    # 4. Detection_Event -- has -- Correlation_Evidence
    draw_line((20.2, entities["Detection_Event"]["cy"] - entities["Detection_Event"]["h"] / 2), (20.2, relationships["has"]["cy"] + relationships["has"]["h"] / 2))
    draw_line((20.2, relationships["has"]["cy"] - relationships["has"]["h"] / 2), (20.2, entities["Correlation_Evidence"]["cy"] + entities["Correlation_Evidence"]["h"] / 2))
    draw_cardinality("1", (20.5, 11.5))
    draw_cardinality("N", (20.5, 8.5))

    # 5. Detection_Event -- triggers -- Mitigation_Action
    # Orthogonal / angled routing matching reference
    det_bottom = (18.6, entities["Detection_Event"]["cy"] - entities["Detection_Event"]["h"] / 2)
    trig_top = (18.6, relationships["triggers"]["cy"] + relationships["triggers"]["h"] / 2)
    trig_bottom = (18.6, relationships["triggers"]["cy"] - relationships["triggers"]["h"] / 2)
    mit_top = (18.6, entities["Mitigation_Action"]["cy"] + entities["Mitigation_Action"]["h"] / 2)

    draw_line(det_bottom, trig_top)
    draw_line(trig_bottom, mit_top)
    draw_cardinality("1", (18.9, 11.2))
    draw_cardinality("0..N", (18.9, 3.8))

    # 6. Mitigation_Action -- generates -- Security_Log
    draw_line((entities["Security_Log"]["cx"] + entities["Security_Log"]["w"] / 2, 2.6), (relationships["generates"]["cx"] - relationships["generates"]["w"] / 2, 2.6))
    draw_line((relationships["generates"]["cx"] + relationships["generates"]["w"] / 2, 2.6), (entities["Mitigation_Action"]["cx"] - entities["Mitigation_Action"]["w"] / 2, 2.6))
    draw_cardinality("N", (9.2, 2.9))
    draw_cardinality("1", (14.4, 2.9))

    # 7. Network_Node -- receives -- Security_Log
    # Left edge from Network_Node down through 'receives' to Security_Log
    nn_bottom = (3.8, entities["Network_Node"]["cy"] - entities["Network_Node"]["h"] / 2)
    rec_top = (3.8, relationships["receives"]["cy"] + relationships["receives"]["h"] / 2)
    rec_bottom = (3.8, relationships["receives"]["cy"] - relationships["receives"]["h"] / 2)
    sec_left = (entities["Security_Log"]["cx"] - entities["Security_Log"]["w"] / 2, 2.6)

    draw_line(nn_bottom, rec_top)
    # Angled connector to Security_Log
    draw_line(rec_bottom, (3.8, 2.6))
    draw_line((3.8, 2.6), sec_left)
    draw_cardinality("1", (4.1, 11.3))
    draw_cardinality("N", (4.5, 2.9))

    # ─────────────────────────────────────────────────────────────────────────────
    # Attribute Definitions: (parent_entity, text, cx, cy, w, h)
    # ─────────────────────────────────────────────────────────────────────────────
    attributes = [
        # Network_Node attributes (fanned above)
        ("Network_Node", "ip_address", 2.0, 15.6, 2.3, 0.75),
        ("Network_Node", "node_type", 3.8, 15.6, 2.2, 0.75),
        ("Network_Node", "status", 5.6, 15.6, 2.0, 0.75),

        # Traffic_Flow attributes (fanned above in 2 graceful tiers matching reference)
        ("Traffic_Flow", "source_ip", 8.8, 16.0, 2.2, 0.75),
        ("Traffic_Flow", "destination_ip", 11.2, 16.0, 2.5, 0.75),
        ("Traffic_Flow", "source_port", 13.8, 16.0, 2.3, 0.75),
        ("Traffic_Flow", "destination_port", 8.6, 14.7, 2.5, 0.75),
        ("Traffic_Flow", "protocol", 11.2, 14.7, 2.0, 0.75),
        ("Traffic_Flow", "packet_count", 13.6, 14.7, 2.4, 0.75),
        ("Traffic_Flow", "byte_count", 9.6, 13.8, 2.2, 0.75),
        ("Traffic_Flow", "timestamp", 12.8, 13.8, 2.2, 0.75),

        # Detection_Event attributes (fanned above)
        ("Detection_Event", "attack_type", 17.4, 16.0, 2.3, 0.75),
        ("Detection_Event", "anomaly_score", 20.0, 16.0, 2.5, 0.75),
        ("Detection_Event", "confidence", 17.2, 14.7, 2.2, 0.75),
        ("Detection_Event", "detection_status", 22.4, 14.7, 2.6, 0.75),
        ("Detection_Event", "timestamp", 20.0, 14.0, 2.2, 0.75),

        # Detection_Model attributes (fanned around)
        ("Detection_Model", "model_name", 9.4, 8.8, 2.3, 0.75),
        ("Detection_Model", "model_type", 14.6, 8.8, 2.3, 0.75),
        ("Detection_Model", "model_status", 9.2, 6.0, 2.4, 0.75),
        ("Detection_Model", "version", 14.8, 6.0, 2.1, 0.75),

        # Correlation_Evidence attributes (fanned below)
        ("Correlation_Evidence", "correlation_score", 18.0, 5.7, 2.6, 0.75),
        ("Correlation_Evidence", "evidence_type", 22.4, 5.7, 2.4, 0.75),
        ("Correlation_Evidence", "details", 18.0, 4.4, 2.0, 0.75),
        ("Correlation_Evidence", "timestamp", 22.4, 4.4, 2.2, 0.75),

        # Mitigation_Action attributes (fanned below & right)
        ("Mitigation_Action", "action_type", 22.0, 2.8, 2.2, 0.75),
        ("Mitigation_Action", "flow_rule", 22.0, 1.8, 2.1, 0.75),
        ("Mitigation_Action", "authorization_status", 14.8, 0.9, 2.7, 0.75),
        ("Mitigation_Action", "action_status", 19.2, 0.9, 2.4, 0.75),
        ("Mitigation_Action", "timestamp", 17.0, 0.2, 2.2, 0.75),

        # Security_Log attributes (fanned below)
        ("Security_Log", "event_type", 4.2, 0.9, 2.2, 0.75),
        ("Security_Log", "severity", 6.8, 0.9, 2.0, 0.75),
        ("Security_Log", "details", 9.4, 0.9, 2.0, 0.75),
        ("Security_Log", "timestamp", 12.0, 0.9, 2.2, 0.75),
    ]

    # Draw Attribute lines to entities
    for ent_name, attr_name, ax_c, ay_c, aw, ah in attributes:
        ent = entities[ent_name]
        # Choose closest anchor point on entity
        ex, ey = ent["cx"], ent["cy"]
        ew_half, eh_half = ent["w"] / 2, ent["h"] / 2

        # Connect to entity boundary
        # If attribute is above entity
        if ay_c > ey + eh_half:
            anchor = (min(max(ax_c, ex - ew_half), ex + ew_half), ey + eh_half)
        # If attribute is below entity
        elif ay_c < ey - eh_half:
            anchor = (min(max(ax_c, ex - ew_half), ex + ew_half), ey - eh_half)
        # If attribute is to the right
        elif ax_c > ex + ew_half:
            anchor = (ex + ew_half, min(max(ay_c, ey - eh_half), ey + eh_half))
        else:
            anchor = (ex - ew_half, min(max(ay_c, ey - eh_half), ey + eh_half))

        ax.plot([anchor[0], ax_c], [anchor[1], ay_c], color="#334155", lw=ATTR_LINE_W, zorder=2)

    # ─────────────────────────────────────────────────────────────────────────────
    # Draw Attribute Ellipses
    # ─────────────────────────────────────────────────────────────────────────────
    for ent_name, attr_name, ax_c, ay_c, aw, ah in attributes:
        ellipse = Ellipse(
            (ax_c, ay_c),
            width=aw,
            height=ah,
            facecolor=ELLIPSE_BG,
            edgecolor="#0f172a",
            lw=BOX_BORDER_W * 0.85,
            zorder=4,
        )
        ax.add_patch(ellipse)
        ax.text(
            ax_c,
            ay_c,
            attr_name,
            fontsize=ATTR_FONT_SIZE,
            fontweight="normal",
            fontfamily=FONT_FAMILY,
            color=TEXT_COLOR,
            ha="center",
            va="center",
            zorder=5,
        )

    # ─────────────────────────────────────────────────────────────────────────────
    # Draw Relationship Diamonds
    # ─────────────────────────────────────────────────────────────────────────────
    for rel_name, rel in relationships.items():
        rx, ry, rw, rh = rel["cx"], rel["cy"], rel["w"], rel["h"]
        diamond_pts = [
            (rx, ry + rh / 2),
            (rx + rw / 2, ry),
            (rx, ry - rh / 2),
            (rx - rw / 2, ry),
        ]
        poly = Polygon(
            diamond_pts,
            closed=True,
            facecolor=DIAMOND_BG,
            edgecolor="#0f172a",
            lw=BOX_BORDER_W,
            zorder=4,
        )
        ax.add_patch(poly)
        ax.text(
            rx,
            ry,
            rel_name,
            fontsize=REL_FONT_SIZE,
            fontweight="normal",
            fontfamily=FONT_FAMILY,
            color=TEXT_COLOR,
            ha="center",
            va="center",
            zorder=5,
        )

    # ─────────────────────────────────────────────────────────────────────────────
    # Draw Entity Rectangles
    # ─────────────────────────────────────────────────────────────────────────────
    for ent_name, ent in entities.items():
        ex, ey, ew, eh = ent["cx"], ent["cy"], ent["w"], ent["h"]
        rect = Rectangle(
            (ex - ew / 2, ey - eh / 2),
            width=ew,
            height=eh,
            facecolor=BOX_BG,
            edgecolor="#0f172a",
            lw=BOX_BORDER_W,
            zorder=4,
        )
        ax.add_patch(rect)
        ax.text(
            ex,
            ey,
            ent_name,
            fontsize=ENTITY_FONT_SIZE,
            fontweight="bold",
            fontfamily=FONT_FAMILY,
            color=TEXT_COLOR,
            ha="center",
            va="center",
            zorder=5,
        )

    # Save PNG and SVG
    plt.tight_layout()
    plt.savefig(PNG_PATH, dpi=300, bbox_inches="tight", facecolor="white")
    plt.savefig(SVG_PATH, format="svg", bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"Generated: {PNG_PATH}")
    print(f"Generated: {SVG_PATH}")

    # Copy to brain artifact directory
    import shutil
    try:
        shutil.copyfile(PNG_PATH, BRAIN_PNG)
        shutil.copyfile(SVG_PATH, BRAIN_SVG)
        print(f"Copied to brain: {BRAIN_PNG}")
    except Exception as e:
        print(f"Warning copying to brain: {e}")


if __name__ == "__main__":
    create_er_diagram()

