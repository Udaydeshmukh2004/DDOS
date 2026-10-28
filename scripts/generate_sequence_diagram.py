"""
IntelliShield SDN — UML Sequence Diagram Generator
Generates Figure 4.2.1: End-to-End Sequence Diagram for IntelliShield SDN
Matching MCA Dissertation / IEEE Research Paper formatting.
"""

import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches

# Set high-quality font and rendering settings
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 9.5
plt.rcParams['axes.linewidth'] = 1.0

# ─── Participant Lifelines ───────────────────────────────────────────────────
participants = [
    "User\n(Admin/Analyst)",
    "SOC Dashboard\n(FastAPI UI :8080)",
    "SDN Controller\n(flow_monitor)",
    "OpenFlow Switch\n(Mininet OVS Fabric)",
    "Detection Engine\n(Entropy+ML+SSL)",
    "Correlation & Fusion\n(R4 & R6 Engines)",
    "Verification Gate\n(R7 Multi-Stage)",
    "Mitigation & Alerts\n(FlowBlocker+R5/R8)"
]

n_part = len(participants)
fig_width = 16.0
fig_height = 20.0

fig, ax = plt.subplots(figsize=(fig_width, fig_height), dpi=300)
fig.patch.set_facecolor('white')
ax.set_facecolor('white')

# Coordinates
x_coords = [1.2 + i * 1.95 for i in range(n_part)]
y_top = 18.8
y_bottom = 0.8

# Draw Participant Boxes at Top
box_width = 1.70
box_height = 0.65

for i, (name, x) in enumerate(zip(participants, x_coords)):
    # Top Box
    rect = patches.FancyBboxPatch(
        (x - box_width/2, y_top - box_height/2), box_width, box_height,
        boxstyle="round,pad=0.08,rounding_size=0.05",
        facecolor="#f8fafc", edgecolor="#1e293b", linewidth=1.4, zorder=4
    )
    ax.add_patch(rect)
    ax.text(x, y_top, name, ha='center', va='center', fontsize=9.0, fontweight='bold', color='#0f172a', zorder=5)

    # Lifeline (vertical dashed line)
    ax.plot([x, x], [y_top - box_height/2, y_bottom], color='#64748b', linestyle='--', linewidth=1.2, zorder=1)

# Sequence Messages: (step_no, text, from_idx, to_idx, is_return, is_self_loop, has_activation)
# y positions descend from 18.0 down to 1.2
steps = [
    (1, "1. Open dashboard", 0, 1, False, False),
    (2, "2. Login (credentials)", 0, 1, False, False),
    (3, "3. Validate credentials & token", 1, 1, False, True),
    (4, "4. Login success", 1, 0, True, False),
    (5, "5. Start monitoring session", 0, 1, False, False),
    (6, "6. Subscribe to telemetry stream", 1, 2, False, False),
    (7, "7. Send OFPPortStats & OFPFlowStats Request", 2, 3, False, False),
    (8, "8. Return flow & port statistics", 3, 2, True, False),
    (9, "9. Extract 15-D feature vector", 2, 2, False, True),
    (10, "10. Forward telemetry for detection", 2, 4, False, False),
    (11, "11. Compute Shannon Entropy (5-dim)", 4, 4, False, True),
    (12, "12. Predict ML status & confidence", 4, 4, False, True),
    (13, "13. SSL Autoencoder reconstruction MSE", 4, 4, False, True),
    (14, "14. Detection results (ML, Entropy, SSL)", 4, 2, True, False),
    (15, "15. Send signals for cross-layer correlation", 2, 5, False, False),
    (16, "16. Correlate IP/port co-occurrence (R4)", 5, 5, False, True),
    (17, "17. Reliability-weighted collaborative fusion (R6)", 5, 5, False, True),
    (18, "18. Fused decision (ATTACK / NORMAL)", 5, 2, True, False),
    (19, "19. Submit for multi-stage verification", 2, 6, False, False),
    (20, "20. Evaluate warmup, streak & confidence (R7)", 6, 6, False, True),
    (21, "21. Verification result: ATTACK confirmed", 6, 2, True, False),
    (22, "22. Dispatch mitigation action", 2, 7, False, False),
    (23, "23. Determine surgical match (FLOW_PAIR)", 7, 7, False, True),
    (24, "24. Install OFPFlowMod DROP rule", 7, 3, False, False),
    (25, "25. DROP rule installed & active", 3, 7, True, False),
    (26, "26. Generate XAI feature importance (R5)", 7, 7, False, True),
    (27, "27. Store incident JSONL & dispatch alert (R8)", 7, 7, False, True),
    (28, "28. Mitigation & alert response", 7, 2, True, False),
    (29, "29. Push real-time event & telemetry", 2, 1, True, False),
    (30, "30. Display attack & mitigation on dashboard", 1, 0, True, False),
    (31, "31. Inspect blocked flows / RCA report", 0, 1, False, False),
    (32, "32. Request active block list & RCA data", 1, 2, False, False),
    (33, "33. Return active block list & RCA data", 2, 1, True, False),
    (34, "34. Display RCA explanation & flow stats", 1, 0, True, False),
    (35, "35. Logout", 0, 1, False, False),
    (36, "36. End session & close socket", 1, 0, True, False)
]

n_steps = len(steps)
y_start = 18.0
y_step = (y_start - 1.2) / n_steps

# Track activations
activations = {}

for idx, (num, text, f_idx, t_idx, is_return, is_self) in enumerate(steps):
    y = y_start - idx * y_step
    x1 = x_coords[f_idx]
    x2 = x_coords[t_idx]

    if is_self:
        # Self call loop
        loop_w = 0.35
        loop_h = y_step * 0.70
        ax.plot([x1, x1 + loop_w, x1 + loop_w, x1],
                [y, y, y - loop_h, y - loop_h],
                color='#1e293b', linewidth=1.2, zorder=3)
        # Arrowhead
        ax.annotate('', xy=(x1, y - loop_h), xytext=(x1 + 0.08, y - loop_h),
                    arrowprops=dict(arrowstyle="-|>", color='#1e293b', lw=1.2, mutation_scale=10),
                    zorder=4)
        ax.text(x1 + loop_w + 0.08, y - loop_h/2, text,
                va='center', ha='left', fontsize=8.2, fontweight='bold', color='#1e293b')
    else:
        # Message Arrow
        linestyle = '--' if is_return else '-'
        color = '#334155' if is_return else '#0f172a'
        arrowstyle = "-|>" if not is_return else "-|>"

        # Draw line with arrow
        if x1 < x2:
            ax.annotate('', xy=(x2, y), xytext=(x1, y),
                        arrowprops=dict(arrowstyle=arrowstyle, color=color,
                                       linestyle=linestyle, lw=1.3, mutation_scale=11),
                        zorder=3)
            ax.text((x1 + x2)/2, y + 0.10, text,
                    ha='center', va='bottom', fontsize=8.2, fontweight='bold', color='#0f172a', zorder=5)
        else:
            ax.annotate('', xy=(x2, y), xytext=(x1, y),
                        arrowprops=dict(arrowstyle=arrowstyle, color=color,
                                       linestyle=linestyle, lw=1.3, mutation_scale=11),
                        zorder=3)
            ax.text((x1 + x2)/2, y + 0.10, text,
                    ha='center', va='bottom', fontsize=8.2, fontweight='bold', color='#0f172a', zorder=5)

# Add activation boxes on key lifelines
act_boxes = [
    (0, 18.0, 16.8),   # User login
    (1, 18.0, 16.5),   # Dashboard
    (2, 15.6, 6.2),    # Controller main cycle
    (3, 15.2, 14.2),   # Switch stats
    (4, 13.9, 11.5),   # Detection engine
    (5, 11.2, 9.4),    # Fusion engine
    (6, 9.0, 7.8),     # Verification gate
    (7, 7.5, 4.8),     # Mitigation engine
    (3, 6.5, 5.8),     # Switch drop
    (1, 4.5, 3.8),     # Dashboard notify
    (0, 3.5, 0.9),     # User inspection & logout
]

for p_idx, y_top_act, y_bot_act in act_boxes:
    x = x_coords[p_idx]
    h = y_top_act - y_bot_act
    rect = patches.Rectangle((x - 0.08, y_bot_act), 0.16, h,
                             facecolor='#e2e8f0', edgecolor='#475569', linewidth=1.0, zorder=2)
    ax.add_patch(rect)

# Clean plot aesthetics
ax.set_xlim(0, fig_width)
ax.set_ylim(0, 19.8)
ax.axis('off')

# Title & Caption
fig.text(0.50, 0.985, 'Figure 4.2.1 — End-to-End Operational Sequence Diagram for IntelliShield SDN',
         ha='center', fontsize=13, fontweight='bold', fontfamily='DejaVu Sans', color='#0f172a')

# Output directories
output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '08_Presentation')
os.makedirs(output_dir, exist_ok=True)

png_path = os.path.join(output_dir, 'Figure_4_2_1_IntelliShield_Sequence_Diagram.png')
pdf_path = os.path.join(output_dir, 'Figure_4_2_1_IntelliShield_Sequence_Diagram.pdf')

plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
plt.close()

print("Successfully generated:")
print(f"  PNG: {png_path}")
print(f"  PDF: {pdf_path}")

