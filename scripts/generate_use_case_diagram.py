"""
IntelliShield SDN — UML Use Case Diagram Generator (No Login / Logout)
Generates Figure 5.1: Use Case Diagram for IntelliShield SDN
Matching the exact layout, structure, and style of the uploaded reference diagram (Figure 5.1).
No Login or Logout use cases — 100% verified SDN engineering capabilities.
Outputs:
  - PROJECT_DOCS/08_Presentation/Figure_5_1_IntelliShield_Use_Case_Diagram.png (300 DPI)
  - PROJECT_DOCS/08_Presentation/Figure_5_1_IntelliShield_Use_Case_Diagram.pdf (Vector)
  - Desktop copies for direct user access
"""

import os
import shutil
import matplotlib.pyplot as plt
import matplotlib.patches as patches

def draw_stick_figure(ax, x, y, label, scale=1.0):
    """
    Draw a clean, classic UML stick figure actor at (x, y) with a text label below.
    """
    head_radius = 0.22 * scale
    head_center_y = y + 0.85 * scale
    neck_y = head_center_y - head_radius
    pelvis_y = y + 0.15 * scale
    shoulder_y = y + 0.55 * scale
    foot_y = y - 0.45 * scale
    arm_span = 0.35 * scale
    leg_span = 0.30 * scale
    
    # Head
    head = patches.Circle((x, head_center_y), head_radius,
                          facecolor='white', edgecolor='#1e293b', linewidth=1.5, zorder=6)
    ax.add_patch(head)
    
    # Torso
    ax.plot([x, x], [neck_y, pelvis_y], color='#1e293b', linewidth=1.6, zorder=6)
    
    # Arms (angled slightly down like classic UML stick figure)
    ax.plot([x - arm_span, x, x + arm_span],
            [shoulder_y - 0.15 * scale, shoulder_y, shoulder_y - 0.15 * scale],
            color='#1e293b', linewidth=1.6, zorder=6)
    
    # Legs
    ax.plot([x - leg_span, x, x + leg_span],
            [foot_y, pelvis_y, foot_y],
            color='#1e293b', linewidth=1.6, zorder=6)
    
    # Label below
    ax.text(x, foot_y - 0.38 * scale, label,
            ha='center', va='top', fontsize=11.0, fontweight='bold', fontfamily='DejaVu Sans',
            color='#0f172a', zorder=6)

def generate_use_case_diagram():
    fig_width = 11.2
    fig_height = 14.5
    
    fig, ax = plt.subplots(figsize=(fig_width, fig_height), dpi=300)
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    
    # System boundary box dimensions
    box_x = 2.45
    box_y = 1.05
    box_w = 6.30
    box_h = 12.2
    
    # 1. System Boundary Box (Rectangle)
    boundary = patches.Rectangle((box_x, box_y), box_w, box_h,
                                 facecolor='white', edgecolor='#1e293b',
                                 linewidth=1.4, zorder=2)
    ax.add_patch(boundary)
    
    # Package tab at top-left of the boundary
    tab_w = 1.95
    tab_h = 0.40
    tab_pts = [
        [box_x, box_y + box_h],
        [box_x, box_y + box_h - tab_h],
        [box_x + tab_w - 0.22, box_y + box_h - tab_h],
        [box_x + tab_w, box_y + box_h - tab_h + 0.12],
        [box_x + tab_w, box_y + box_h],
        [box_x, box_y + box_h]
    ]
    tab_polygon = patches.Polygon(tab_pts, closed=True,
                                  facecolor='#ffffff', edgecolor='#1e293b',
                                  linewidth=1.2, zorder=3)
    ax.add_patch(tab_polygon)
    ax.text(box_x + tab_w / 2 - 0.05, box_y + box_h - tab_h / 2 + 0.02, 'IntelliShield-SDN',
            ha='center', va='center', fontsize=9.8, fontweight='bold',
            fontfamily='DejaVu Sans', color='#1e293b', zorder=4)

    # 2. Use Cases (Vertical stack of 11 authentic SDN use cases - NO login/logout)
    center_x = box_x + box_w / 2
    
    use_cases = [
        "Monitor Network Traffic & Flow Stats",
        "Analyze Shannon Traffic Entropy",
        "Detect DDoS Attacks via ML & SSL",
        "Correlate & Fuse Cross-Layer Signals",
        "Verify Suspicious Traffic (Multi-Stage)",
        "View Real-Time SOC Dashboard",
        "View XAI Explanations & Root Cause",
        "Review Quarantined & Blocked Flows",
        "Apply OpenFlow Mitigation Rules",
        "Configure Monitoring & Drift Thresholds",
        "Export Security Alerts & Audit Logs"
    ]
    
    n_uc = len(use_cases)
    # Distribute y-positions inside the boundary
    y_start = box_y + box_h - 0.88
    y_end = box_y + 0.68
    y_step = (y_start - y_end) / (n_uc - 1)
    
    uc_positions = []
    oval_w = 4.25
    oval_h = 0.64
    
    for i, uc_text in enumerate(use_cases):
        uc_y = y_start - i * y_step
        uc_positions.append((center_x, uc_y))
        
        # Use Case Oval (Ellipse)
        ellipse = patches.Ellipse((center_x, uc_y), oval_w, oval_h,
                                  facecolor='#ffffff', edgecolor='#1e293b',
                                  linewidth=1.3, zorder=4)
        ax.add_patch(ellipse)
        
        # Text inside oval
        ax.text(center_x, uc_y, uc_text,
                ha='center', va='center', fontsize=8.8, fontweight='bold',
                fontfamily='DejaVu Sans', color='#0f172a', zorder=5)

    # 3. Actors: Left and Right
    left_actor_x = 1.30
    left_actor_y = box_y + box_h * 0.50
    draw_stick_figure(ax, left_actor_x, left_actor_y, "Security Analyst /\nOperator", scale=1.05)
    
    right_actor_x = 9.85
    right_actor_y = box_y + box_h * 0.50
    draw_stick_figure(ax, right_actor_x, right_actor_y, "Admin", scale=1.05)
    
    # Actor hand / connection coordinate anchors
    left_hand = (left_actor_x + 0.38, left_actor_y + 0.40)
    right_hand = (right_actor_x - 0.38, right_actor_y + 0.40)
    
    # 4. Connection Lines (Actor to Use Case edges)
    # Left Actor Connections:
    # 0: Monitor Network Traffic & Flow Stats
    # 1: Analyze Shannon Traffic Entropy
    # 2: Detect DDoS Attacks via ML & SSL
    # 3: Correlate & Fuse Cross-Layer Signals
    # 4: Verify Suspicious Traffic (Multi-Stage)
    # 5: View Real-Time SOC Dashboard
    # 10: Export Security Alerts & Audit Logs
    left_connected_indices = [0, 1, 2, 3, 4, 5, 10]
    
    for idx in left_connected_indices:
        cx, cy = uc_positions[idx]
        edge_x = cx - oval_w / 2 + 0.06
        ax.plot([left_hand[0], edge_x], [left_hand[1], cy],
                color='#1e293b', linewidth=1.3, linestyle='-', zorder=3)
        
    # Right Actor (Admin) Connections:
    # 0: Monitor Network Traffic & Flow Stats
    # 5: View Real-Time SOC Dashboard
    # 6: View XAI Explanations & Root Cause
    # 7: Review Quarantined & Blocked Flows
    # 8: Apply OpenFlow Mitigation Rules
    # 9: Configure Monitoring & Drift Thresholds
    # 10: Export Security Alerts & Audit Logs
    right_connected_indices = [0, 5, 6, 7, 8, 9, 10]
    
    for idx in right_connected_indices:
        cx, cy = uc_positions[idx]
        edge_x = cx + oval_w / 2 - 0.06
        ax.plot([right_hand[0], edge_x], [right_hand[1], cy],
                color='#1e293b', linewidth=1.3, linestyle='-', zorder=3)

    # Clean axes
    ax.set_xlim(0, fig_width)
    ax.set_ylim(0, fig_height)
    ax.axis('off')
    
    # 5. Caption at Bottom: "Figure 5.1: Use case diagram"
    fig.text(0.50, 0.035, 'Figure 5.1: Use case diagram',
             ha='center', va='center', fontsize=13.5, fontweight='bold', fontstyle='italic',
             fontfamily='serif', color='#002060')
    
    # Save outputs
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '08_Presentation')
    os.makedirs(output_dir, exist_ok=True)
    
    png_path = os.path.join(output_dir, 'Figure_5_1_IntelliShield_Use_Case_Diagram.png')
    pdf_path = os.path.join(output_dir, 'Figure_5_1_IntelliShield_Use_Case_Diagram.pdf')
    
    plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    
    print(f"[OK] Generated PNG: {png_path}")
    print(f"[OK] Generated PDF: {pdf_path}")

if __name__ == '__main__':
    generate_use_case_diagram()
