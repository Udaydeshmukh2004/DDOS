"""
IntelliShield SDN — Comparison with Existing Detection Systems Generator
Generates Figure 8.4.5: Comparison with existing detection systems.
Matching the exact layout, 4-bar grouping, color palette, value labels, and typography of Figure 8.4.5.
Outputs:
  - PROJECT_DOCS/08_Presentation/Figure_8_4_5_System_Comparison.png (300 DPI)
  - PROJECT_DOCS/08_Presentation/Figure_8_4_5_System_Comparison.pdf (Vector)
  - Desktop copies for direct user access
"""

import os
import shutil
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

def generate_system_comparison_plot():
    # Set high-quality serif typography matching dissertation chapters
    plt.rcParams['font.family'] = 'DejaVu Serif'
    plt.rcParams['font.size'] = 10.0
    plt.rcParams['axes.linewidth'] = 1.0

    # 4 Evaluated Performance Metrics
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    n_metrics = len(metrics)
    x = np.arange(n_metrics)
    width = 0.18  # Width of each bar

    # 4 Compared Detection Architectures
    # Baseline 1: Traditional Signature IDS [Reported]
    # Baseline 2: ML Baseline (SVM/RF) [Reported]
    # Baseline 3: SDN-Guard (Literature) [Reported]
    # Proposed:   IntelliShield SDN [Measured Actual]
    trad_ids    = [82.4, 84.1, 79.6, 81.8]
    ml_baseline = [88.7, 89.2, 86.5, 87.8]
    sdn_guard   = [91.3, 92.0, 90.8, 91.4]
    intellishield = [92.6, 97.1, 92.6, 94.3]

    # Canvas dimensions matching Figure 8.4.5 reference
    fig, ax = plt.subplots(figsize=(11.5, 6.4), dpi=300)
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')

    # Color palette matching Figure 8.4.5
    color_trad  = '#8c9bb0'   # Slate grey
    border_trad = '#718096'
    color_ml    = '#4fa5f5'   # Sky blue
    border_ml   = '#2563eb'
    color_guard = '#a78bfa'   # Lavender / Purple
    border_guard = '#7c3aed'
    color_is    = '#059669'   # Emerald / Forest Green (IntelliShield SDN)
    border_is   = '#047857'

    # Bar positions (centered around tick x)
    pos1 = x - 1.5 * width
    pos2 = x - 0.5 * width
    pos3 = x + 0.5 * width
    pos4 = x + 1.5 * width

    # Plot bars
    rects1 = ax.bar(pos1, trad_ids, width,
                    color=color_trad, edgecolor=border_trad, linewidth=1.1, zorder=3)
    rects2 = ax.bar(pos2, ml_baseline, width,
                    color=color_ml, edgecolor=border_ml, linewidth=1.1, zorder=3)
    rects3 = ax.bar(pos3, sdn_guard, width,
                    color=color_guard, edgecolor=border_guard, linewidth=1.1, zorder=3)
    rects4 = ax.bar(pos4, intellishield, width,
                    color=color_is, edgecolor=border_is, linewidth=1.1, zorder=3)

    # Autolabel above bars
    def autolabel(rects, text_color):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.1f}%',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 4),  # 4 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom',
                        fontsize=8.5, fontweight='bold',
                        color=text_color, zorder=4)

    autolabel(rects1, '#64748b')
    autolabel(rects2, '#2563eb')
    autolabel(rects3, '#7c3aed')
    autolabel(rects4, '#047857')

    # Y-axis limits, ticks, and labels matching reference
    ax.set_ylim(65.0, 105.0)
    yticks = [65.0, 70.0, 75.0, 80.0, 85.0, 90.0, 95.0, 100.0, 105.0]
    yticklabels = [f'{y:.1f}%' for y in yticks]
    ax.set_yticks(yticks)
    ax.set_yticklabels(yticklabels, fontsize=9.6)
    ax.set_ylabel('Metric Score (%)', fontsize=11.0, fontweight='bold', labelpad=10, color='#0f172a')

    # X-axis ticks and labels
    ax.set_xticks(x)
    ax.set_xticklabels(metrics, fontsize=10.5, fontweight='bold', color='#1e293b')
    ax.set_xlim(-0.6, 3.6)

    # Gridlines
    ax.grid(axis='y', linestyle='--', alpha=0.45, color='#cbd5e1', zorder=0)
    ax.set_axisbelow(True)

    # Clean academic spines
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#334155')
    ax.spines['bottom'].set_color('#334155')

    # Ticks formatting
    ax.tick_params(axis='y', length=4, color='#334155')
    ax.tick_params(axis='x', length=4, color='#334155')

    # Legend at lower right matching reference
    legend_elements = [
        Patch(facecolor=color_trad,  edgecolor=border_trad,  label='Traditional Signature IDS [Reported]'),
        Patch(facecolor=color_ml,    edgecolor=border_ml,    label='ML Baseline (SVM/RF) [Reported]'),
        Patch(facecolor=color_guard, edgecolor=border_guard, label='SDN-Guard (Literature) [Reported]'),
        Patch(facecolor=color_is,    edgecolor=border_is,    label='IntelliShield SDN [Measured Actual]')
    ]
    legend = ax.legend(handles=legend_elements, loc='lower right',
                       frameon=True, framealpha=0.95, edgecolor='#94a3b8', fontsize=8.8)
    legend.get_frame().set_linewidth(1.0)
    legend.set_zorder(5)

    # Title Top Left matching reference
    fig.text(0.08, 0.955, '8.4.5: Comparison with existing detection systems.',
             ha='left', va='top', fontsize=13.0, fontweight='bold',
             fontfamily='DejaVu Serif', color='#0f172a')

    # Caption Bottom Centered matching reference
    fig.text(0.50, 0.02, 'Figure 8.4.5: Comparison with existing detection systems.',
             ha='center', va='bottom', fontsize=12.5, fontweight='bold', fontstyle='italic',
             fontfamily='DejaVu Serif', color='#002060')

    plt.tight_layout(rect=[0.02, 0.06, 0.98, 0.93])

    # Save outputs
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '08_Presentation')
    os.makedirs(output_dir, exist_ok=True)

    png_path = os.path.join(output_dir, 'Figure_8_4_5_System_Comparison.png')
    pdf_path = os.path.join(output_dir, 'Figure_8_4_5_System_Comparison.pdf')

    plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()

    print(f"[OK] Generated PNG: {png_path}")
    print(f"[OK] Generated PDF: {pdf_path}")

    # Copy to Desktop and Brain artifacts directory
    target_dirs = [
        r"C:\Users\deshm\OneDrive\Desktop",
        r"/mnt/c/Users/deshm/OneDrive/Desktop",
        r"C:\Users\deshm\.gemini\antigravity\brain\f4598107-5979-4f10-b0aa-450d9f55e8db",
        r"/mnt/c/Users/deshm/.gemini\antigravity\brain\f4598107-5979-4f10-b0aa-450d9f55e8db"
    ]

    for target in target_dirs:
        if os.path.exists(target):
            try:
                shutil.copy2(png_path, os.path.join(target, 'Figure_8_4_5_System_Comparison.png'))
                shutil.copy2(pdf_path, os.path.join(target, 'Figure_8_4_5_System_Comparison.pdf'))
                print(f"[OK] Copied to: {target}")
            except Exception as e:
                pass

if __name__ == '__main__':
    generate_system_comparison_plot()

