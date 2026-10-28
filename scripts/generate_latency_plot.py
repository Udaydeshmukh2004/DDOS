"""
IntelliShield SDN — Latency & Processing Time Performance Generator
Generates Figure 8.3.4: Prediction and End-to-End Processing Latency
Matching the exact layout, structure, color palette, SLA target line, and style of Figure 8.3.4.
Outputs:
  - PROJECT_DOCS/08_Presentation/Figure_8_3_4_Latency_Performance.png (300 DPI)
  - PROJECT_DOCS/08_Presentation/Figure_8_3_4_Latency_Performance.pdf (Vector)
  - Desktop copies for direct user access
"""

import os
import shutil
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

def generate_latency_plot():
    # Set high-quality serif typography matching dissertation chapters
    plt.rcParams['font.family'] = 'DejaVu Serif'
    plt.rcParams['font.size'] = 10.0
    plt.rcParams['axes.linewidth'] = 1.0

    # 4 Statistical Latency Categories
    categories = [
        'Mean',
        'Median',
        '95th Percentile (P95)',
        '99th Percentile (P99)'
    ]

    # Latency Data (in milliseconds)
    # Series 1: Model Prediction Only (Feature extraction, Shannon entropy, LightGBM, SSL Autoencoder, XAI TreeSHAP)
    # Series 2: End-to-End Flow Processing (Ingestion, detection pipeline, verification gate, OFPFlowMod drop installation)
    model_prediction = [68.4, 56.6, 113.4, 125.2]
    e2e_processing   = [57.2, 55.7,  66.4,  76.2]

    x = np.arange(len(categories))
    width = 0.30  # Width of individual bars

    # Canvas dimensions matching Figure 8.3.4
    fig, ax = plt.subplots(figsize=(10.2, 5.8), dpi=300)
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')

    # Color definitions matching Figure 8.3.4 reference
    color_model = '#007b99'       # Deep Teal / Dark Cyan
    border_model = '#005b73'
    color_e2e   = '#c75b12'       # Warm Amber / Rust Brown
    border_e2e   = '#99430c'
    color_sla   = '#b91c1c'       # Crimson Red for 100 ms SLA Target

    # Plot Bars
    rects1 = ax.bar(x - width/2, model_prediction, width,
                    label='Model Prediction Only',
                    color=color_model, edgecolor=border_model, linewidth=1.1, zorder=3)
    rects2 = ax.bar(x + width/2, e2e_processing, width,
                    label='End-to-End Flow Processing',
                    color=color_e2e, edgecolor=border_e2e, linewidth=1.1, zorder=3)

    # 100 ms SLA Target Horizontal Line
    sla_line = ax.axhline(y=100.0, color=color_sla, linestyle=':', linewidth=1.6, zorder=4)

    # Value Labels above each bar
    def autolabel(rects, text_color):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.1f} ms',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 4),  # 4 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom',
                        fontsize=9.0, fontweight='bold',
                        color=text_color)

    autolabel(rects1, color_model)
    autolabel(rects2, color_e2e)

    # Axes, Spines, and Ticks
    ax.set_ylabel('Latency (milliseconds)', fontsize=11.5, fontweight='bold', labelpad=10, color='#0f172a')
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=10.0, fontweight='bold', color='#1e293b')
    ax.set_ylim(0, 145)
    ax.set_yticks([0, 20, 40, 60, 80, 100, 120, 140])
    ax.set_yticklabels(['0', '20', '40', '60', '80', '100', '120', '140'], fontsize=10.0)

    # Gridlines: Both horizontal and subtle vertical dashed grid
    ax.grid(axis='y', linestyle='--', alpha=0.55, color='#cbd5e1', zorder=0)
    ax.grid(axis='x', linestyle='--', alpha=0.35, color='#e2e8f0', zorder=0)
    ax.set_axisbelow(True)

    # Clean academic spines
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#334155')
    ax.spines['bottom'].set_color('#334155')

    # Custom Legend (Top Left matching reference)
    legend_elements = [
        Line2D([0], [0], color=color_sla, linestyle=':', linewidth=1.8, label='100 ms SLA Target'),
        Patch(facecolor=color_model, edgecolor=border_model, label='Model Prediction Only'),
        Patch(facecolor=color_e2e, edgecolor=border_e2e, label='End-to-End Flow Processing')
    ]
    legend = ax.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(0.02, 0.98),
                       frameon=True, framealpha=0.95, edgecolor='#94a3b8', fontsize=9.6)
    legend.get_frame().set_linewidth(1.0)

    # Title Top Left matching reference
    fig.text(0.08, 0.96, '8.3.4: Prediction and End-to-End Processing Latency',
             ha='left', va='top', fontsize=13.0, fontweight='bold',
             fontfamily='DejaVu Serif', color='#0f172a')

    # Caption Bottom Centered matching reference
    fig.text(0.50, 0.02, 'Figure 8.3.4: Prediction and End-to-End Processing Latency',
             ha='center', va='bottom', fontsize=12.5, fontweight='bold', fontstyle='italic',
             fontfamily='DejaVu Serif', color='#002060')

    plt.tight_layout(rect=[0.04, 0.06, 0.98, 0.94])

    # Save outputs
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '08_Presentation')
    os.makedirs(output_dir, exist_ok=True)

    png_path = os.path.join(output_dir, 'Figure_8_3_4_Latency_Performance.png')
    pdf_path = os.path.join(output_dir, 'Figure_8_3_4_Latency_Performance.pdf')

    plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()

    print(f"[OK] Generated PNG: {png_path}")
    print(f"[OK] Generated PDF: {pdf_path}")

    # Copy to Desktop
    desktop_dir = r"C:\Users\deshm\OneDrive\Desktop"
    if os.path.exists(desktop_dir):
        dt_png = os.path.join(desktop_dir, 'Figure_8_3_4_Latency_Performance.png')
        dt_pdf = os.path.join(desktop_dir, 'Figure_8_3_4_Latency_Performance.pdf')
        try:
            shutil.copy2(png_path, dt_png)
            shutil.copy2(pdf_path, dt_pdf)
            print(f"[OK] Copied to Desktop: {dt_png}")
            print(f"[OK] Copied to Desktop: {dt_pdf}")
        except Exception as e:
            print(f"[WARN] Desktop copy: {e}")

if __name__ == '__main__':
    generate_latency_plot()

