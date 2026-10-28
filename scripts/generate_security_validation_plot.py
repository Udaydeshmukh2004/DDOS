"""
IntelliShield SDN — Security Feature Validation Results Generator
Generates Figure 8.3.5: Security Feature Validation Results
Matching the exact layout, horizontal bar styling, emerald green color, annotations, and typography of Figure 8.3.5.
Outputs:
  - PROJECT_DOCS/08_Presentation/Figure_8_3_5_Security_Validation.png (300 DPI)
  - PROJECT_DOCS/08_Presentation/Figure_8_3_5_Security_Validation.pdf (Vector)
  - Desktop copies for direct user access
"""

import os
import shutil
import numpy as np
import matplotlib.pyplot as plt

def generate_security_validation_plot():
    # Set high-quality serif typography matching dissertation chapters
    plt.rcParams['font.family'] = 'DejaVu Serif'
    plt.rcParams['font.size'] = 10.0
    plt.rcParams['axes.linewidth'] = 1.0

    # 10 Core Security Features in IntelliShield SDN (ordered top to bottom)
    features = [
        "TCP SYN Flood Detection",
        "UDP Flood Detection",
        "Burst Attack Detection",
        "Zero-Day SSL Flood Detection",
        "Legitimate Flow Pass-Through",
        "Collaborative Confidence Scoring",
        "Multi-Stage Threat Verification",
        "Mitigation Engine — DROP",
        "Mitigation Engine — ALLOW",
        "Quarantine Low Confidence"
    ]

    n_features = len(features)
    y_pos = np.arange(n_features)
    bar_height = 0.52

    # Canvas dimensions matching Figure 8.3.5
    fig, ax = plt.subplots(figsize=(10.5, 6.2), dpi=300)
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')

    # Color definitions matching Figure 8.3.5 reference
    color_pass = '#16a34a'       # Vibrant Emerald Green
    border_pass = '#15803d'

    # Plot horizontal bars (all 100% verified pass)
    bars = ax.barh(y_pos, [1.0] * n_features, height=bar_height,
                   color=color_pass, edgecolor=border_pass, linewidth=1.1, zorder=3)

    # Invert Y-axis so first feature appears at the top
    ax.invert_yaxis()

    # Annotations: "VERIFIED PASS" centered in each bar
    for i, bar in enumerate(bars):
        ax.text(0.50, bar.get_y() + bar.get_height() / 2, 'VERIFIED PASS',
                ha='center', va='center',
                fontsize=9.6, fontweight='bold', fontfamily='DejaVu Sans',
                color='#ffffff', zorder=5)

    # Axes, Spines, and Ticks
    ax.set_yticks(y_pos)
    ax.set_yticklabels(features, fontsize=9.8, fontweight='bold', color='#1e293b')
    ax.set_xlim(0, 1.0)
    ax.set_xticks([0.0, 1.0])
    ax.set_xticklabels(['FAIL', 'PASS (Verified)'], fontsize=10.0, fontweight='bold', color='#1e293b')
    ax.set_xlabel('Verification Status', fontsize=11.0, fontweight='bold', labelpad=10, color='#0f172a')

    # Gridlines: subtle vertical dashed grid at PASS and horizontal guides
    ax.grid(axis='x', linestyle='--', alpha=0.5, color='#cbd5e1', zorder=0)
    ax.set_axisbelow(True)

    # Clean academic spines
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#334155')
    ax.spines['bottom'].set_color('#334155')

    # Remove tick marks on y-axis for clean look
    ax.tick_params(axis='y', length=4, color='#334155')
    ax.tick_params(axis='x', length=4, color='#334155')

    # Title Top Left matching reference
    fig.text(0.08, 0.96, '8.3.5: Security Feature Validation Results',
             ha='left', va='top', fontsize=13.0, fontweight='bold',
             fontfamily='DejaVu Serif', color='#0f172a')

    # Caption Bottom Centered matching reference
    fig.text(0.50, 0.02, 'Figure 8.3.5: Security Feature Validation Results',
             ha='center', va='bottom', fontsize=12.5, fontweight='bold', fontstyle='italic',
             fontfamily='DejaVu Serif', color='#002060')

    plt.tight_layout(rect=[0.02, 0.06, 0.98, 0.94])

    # Save outputs
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '08_Presentation')
    os.makedirs(output_dir, exist_ok=True)

    png_path = os.path.join(output_dir, 'Figure_8_3_5_Security_Validation.png')
    pdf_path = os.path.join(output_dir, 'Figure_8_3_5_Security_Validation.pdf')

    plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()

    print(f"[OK] Generated PNG: {png_path}")
    print(f"[OK] Generated PDF: {pdf_path}")

    # Copy to Desktop
    desktop_dir = r"C:\Users\deshm\OneDrive\Desktop"
    if os.path.exists(desktop_dir):
        dt_png = os.path.join(desktop_dir, 'Figure_8_3_5_Security_Validation.png')
        dt_pdf = os.path.join(desktop_dir, 'Figure_8_3_5_Security_Validation.pdf')
        try:
            shutil.copy2(png_path, dt_png)
            shutil.copy2(pdf_path, dt_pdf)
            print(f"[OK] Copied to Desktop: {dt_png}")
            print(f"[OK] Copied to Desktop: {dt_pdf}")
        except Exception as e:
            print(f"[WARN] Desktop copy: {e}")

if __name__ == '__main__':
    generate_security_validation_plot()

