"""
IntelliShield SDN — Attack Classification Performance Across Five Classes Generator
Generates Figure 8.4.4: Attack classification performance across five classes.
Matching the exact layout, bar order (Precision, Recall, F1-Score), color palette, value labels, and typography of Figure 8.4.4.
Outputs:
  - PROJECT_DOCS/08_Presentation/Figure_8_4_4_Attack_Classification_Performance.png (300 DPI)
  - PROJECT_DOCS/08_Presentation/Figure_8_4_4_Attack_Classification_Performance.pdf (Vector)
  - Desktop copies for direct user access
"""

import os
import shutil
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

def generate_attack_classification_plot():
    # High-quality academic serif typography matching dissertation chapters
    plt.rcParams['font.family'] = 'DejaVu Serif'
    plt.rcParams['font.size'] = 10.0
    plt.rcParams['axes.linewidth'] = 1.0

    # 5 Verified SDN Scenarios in IntelliShield SDN
    classes = [
        'Normal Traffic\n(NORMAL)',
        'TCP SYN Flood\n(SYN_FLOOD)',
        'UDP Flood\n(UDP_FLOOD)',
        'Burst Attack\n(BURST_FLOOD)',
        'Zero-Day Flood\n(ZERO_DAY_SSL)'
    ]

    # Metrics matching Figure 8.4.4 reference bar order: Precision, Recall, F1-Score
    precision = [99.2, 96.5, 95.2, 55.4, 91.6]
    recall    = [98.2, 95.8, 94.4, 68.2, 94.1]
    f1_score  = [98.7, 96.2, 94.8, 61.1, 92.8]

    n_classes = len(classes)
    x = np.arange(n_classes)
    width = 0.24  # Width of individual bars

    # Canvas dimensions matching Figure 8.4.4 layout
    fig, ax = plt.subplots(figsize=(11.5, 6.4), dpi=300)
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')

    # Color definitions matching Figure 8.4.4 reference
    color_prec  = '#2563eb'     # Vibrant Blue
    border_prec = '#1d4ed8'
    color_rec   = '#16a34a'     # Emerald Green
    border_rec  = '#15803d'
    color_f1    = '#d97706'     # Warm Amber / Orange
    border_f1   = '#b45309'

    # Plot Bars in order: Precision (Left), Recall (Middle), F1-Score (Right)
    rects_prec = ax.bar(x - width, precision, width,
                        color=color_prec, edgecolor=border_prec, linewidth=1.1, zorder=3)
    rects_rec  = ax.bar(x, recall, width,
                        color=color_rec, edgecolor=border_rec, linewidth=1.1, zorder=3)
    rects_f1   = ax.bar(x + width, f1_score, width,
                        color=color_f1, edgecolor=border_f1, linewidth=1.1, zorder=3)

    # Value Labels on top of each bar
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

    autolabel(rects_prec, '#1d4ed8')
    autolabel(rects_rec,  '#15803d')
    autolabel(rects_f1,   '#b45309')

    # Axes, Spines, and Ticks
    ax.set_ylabel('Metric Score (%)', fontsize=11.0, fontweight='bold', labelpad=10, color='#0f172a')
    ax.set_xticks(x)
    ax.set_xticklabels(classes, fontsize=9.8, fontweight='bold', color='#1e293b')
    ax.set_xlim(-0.6, 4.6)
    ax.set_ylim(0, 126)
    ax.set_yticks([0, 20, 40, 60, 80, 100])
    ax.set_yticklabels(['0%', '20%', '40%', '60%', '80%', '100%'], fontsize=9.6)

    # Horizontal dashed gridlines only
    ax.grid(axis='y', linestyle='--', alpha=0.5, color='#cbd5e1', zorder=0)
    ax.set_axisbelow(True)

    # Clean academic spines
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#334155')
    ax.spines['bottom'].set_color('#334155')

    # Tick lines
    ax.tick_params(axis='y', length=4, color='#334155')
    ax.tick_params(axis='x', length=4, color='#334155')

    # Legend at Top Right matching reference with zero overlap on bars
    legend_elements = [
        Patch(facecolor=color_prec, edgecolor=border_prec, label='Precision'),
        Patch(facecolor=color_rec,  edgecolor=border_rec,  label='Recall'),
        Patch(facecolor=color_f1,   edgecolor=border_f1,   label='F1-Score')
    ]
    legend = ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(0.99, 0.98),
                       frameon=True, framealpha=0.95, edgecolor='#cbd5e1', fontsize=9.4)
    legend.get_frame().set_linewidth(1.0)
    legend.set_zorder(5)

    # Title Top Left matching reference
    fig.text(0.08, 0.955, '8.4.4: Attack classification performance across five classes.',
             ha='left', va='top', fontsize=13.0, fontweight='bold',
             fontfamily='DejaVu Serif', color='#0f172a')

    # Caption Bottom Centered matching reference
    fig.text(0.50, 0.02, 'Figure 8.4.4: Attack classification performance across five classes.',
             ha='center', va='bottom', fontsize=12.5, fontweight='bold', fontstyle='italic',
             fontfamily='DejaVu Serif', color='#002060')

    plt.tight_layout(rect=[0.02, 0.06, 0.98, 0.93])

    # Save outputs
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '08_Presentation')
    os.makedirs(output_dir, exist_ok=True)

    png_path = os.path.join(output_dir, 'Figure_8_4_4_Attack_Classification_Performance.png')
    pdf_path = os.path.join(output_dir, 'Figure_8_4_4_Attack_Classification_Performance.pdf')

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
        r"/mnt/c/Users/deshm/.gemini/antigravity/brain/f4598107-5979-4f10-b0aa-450d9f55e8db"
    ]

    for target in target_dirs:
        if os.path.exists(target):
            try:
                shutil.copy2(png_path, os.path.join(target, 'Figure_8_4_4_Attack_Classification_Performance.png'))
                shutil.copy2(pdf_path, os.path.join(target, 'Figure_8_4_4_Attack_Classification_Performance.pdf'))
                print(f"[OK] Copied to: {target}")
            except Exception as e:
                pass

if __name__ == '__main__':
    generate_attack_classification_plot()
