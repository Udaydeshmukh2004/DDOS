"""
IntelliShield SDN — Test Cases by Module Generator
Generates Figure 8.4.1: Test cases by module
Matching the exact layout, grouped bar styling, green/red colors, baseline zero labels, and typography of Figure 8.4.1.
Outputs:
  - PROJECT_DOCS/08_Presentation/Figure_8_4_1_Test_Cases_By_Module.png (300 DPI)
  - PROJECT_DOCS/08_Presentation/Figure_8_4_1_Test_Cases_By_Module.pdf (Vector)
  - Desktop copies for direct user access
"""

import os
import shutil
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

def generate_test_cases_by_module_plot():
    # Set high-quality serif typography matching dissertation chapters
    plt.rcParams['font.family'] = 'DejaVu Serif'
    plt.rcParams['font.size'] = 10.0
    plt.rcParams['axes.linewidth'] = 1.0

    # 8 Core Architectural Modules in IntelliShield SDN
    modules = [
        'Flow Monitor & Telemetry',
        'Entropy Detection Engine',
        'ML & SSL Anomaly Detector',
        'Cross-Layer Correlation',
        'Collaborative Fusion',
        'Multi-Stage Verification',
        'OpenFlow Mitigation',
        'XAI & Security Logging'
    ]

    # Test Case Counts matching Figure 8.4.1 reference distribution
    passed_cases = [6, 6, 6, 6, 6, 5, 6, 5]
    failed_cases = [0, 0, 0, 0, 0, 0, 0, 0]

    n_modules = len(modules)
    x = np.arange(n_modules)
    width = 0.38  # Width of the bars

    # Canvas dimensions matching Figure 8.4.1
    fig, ax = plt.subplots(figsize=(10.5, 6.2), dpi=300)
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')

    # Color definitions matching Figure 8.4.1 reference
    color_pass = '#16a34a'       # Vibrant Emerald Green
    border_pass = '#15803d'
    color_fail = '#dc2626'       # Bold Red
    border_fail = '#b91c1c'

    # Plot Passed Bars (Emerald Green)
    rects_pass = ax.bar(x - width/2, passed_cases, width,
                        color=color_pass, edgecolor=border_pass, linewidth=1.1, zorder=3)

    # Plot Failed Bars (Red, height = 0)
    rects_fail = ax.bar(x + width/2, failed_cases, width,
                        color=color_fail, edgecolor=border_fail, linewidth=1.1, zorder=3)

    # Annotations on top of Passed Bars (Green integers)
    for rect in rects_pass:
        height = rect.get_height()
        ax.annotate(f'{int(height)}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 4),  # 4 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom',
                    fontsize=9.6, fontweight='bold',
                    color='#15803d')

    # Annotations on baseline for Failed Bars (Red zeros)
    for rect in rects_fail:
        ax.annotate('0',
                    xy=(rect.get_x() + rect.get_width() / 2, 0.0),
                    xytext=(0, 4),  # 4 points vertical offset above baseline
                    textcoords="offset points",
                    ha='center', va='bottom',
                    fontsize=9.0, fontweight='bold',
                    color='#dc2626')

    # Axes, Spines, and Ticks
    ax.set_ylabel('Number of Test Cases', fontsize=11.0, fontweight='bold', labelpad=10, color='#0f172a')
    ax.set_xticks(x)
    ax.set_xticklabels(modules, fontsize=9.2, fontweight='bold', color='#1e293b',
                       rotation=22, ha='right')
    ax.set_ylim(0, 8.5)
    ax.set_yticks(np.arange(0, 9))
    ax.set_yticklabels([str(i) for i in range(9)], fontsize=9.8)

    # Horizontal dashed gridlines only
    ax.grid(axis='y', linestyle='--', alpha=0.5, color='#cbd5e1', zorder=0)
    ax.set_axisbelow(True)

    # Clean academic spines
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#334155')
    ax.spines['bottom'].set_color('#334155')

    # Tick line lengths
    ax.tick_params(axis='y', length=4, color='#334155')
    ax.tick_params(axis='x', length=4, color='#334155')

    # Legend at Top Right matching reference
    legend_elements = [
        Patch(facecolor=color_pass, edgecolor=border_pass, label='Passed Test Cases'),
        Patch(facecolor=color_fail, edgecolor=border_fail, label='Failed Test Cases')
    ]
    legend = ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(0.98, 0.96),
                       frameon=True, framealpha=0.95, edgecolor='#94a3b8', fontsize=9.2)
    legend.get_frame().set_linewidth(1.0)

    # Section Headers Top Left matching reference
    fig.text(0.08, 0.96, '8.4 Graphical Analysis of Results',
             ha='left', va='top', fontsize=13.5, fontweight='bold',
             fontfamily='DejaVu Serif', color='#0f172a')
    fig.text(0.08, 0.915, '8.4.1: Test cases by module',
             ha='left', va='top', fontsize=12.2, fontweight='bold',
             fontfamily='DejaVu Serif', color='#0f172a')

    # Caption Bottom Centered matching reference
    fig.text(0.50, 0.02, 'Figure 8.4.1: Test cases by module',
             ha='center', va='bottom', fontsize=12.5, fontweight='bold', fontstyle='italic',
             fontfamily='DejaVu Serif', color='#002060')

    plt.tight_layout(rect=[0.03, 0.06, 0.98, 0.89])

    # Save outputs
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '08_Presentation')
    os.makedirs(output_dir, exist_ok=True)

    png_path = os.path.join(output_dir, 'Figure_8_4_1_Test_Cases_By_Module.png')
    pdf_path = os.path.join(output_dir, 'Figure_8_4_1_Test_Cases_By_Module.pdf')

    plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()

    print(f"[OK] Generated PNG: {png_path}")
    print(f"[OK] Generated PDF: {pdf_path}")

    # Copy to Desktop
    desktop_dir = r"C:\Users\deshm\OneDrive\Desktop"
    if os.path.exists(desktop_dir):
        dt_png = os.path.join(desktop_dir, 'Figure_8_4_1_Test_Cases_By_Module.png')
        dt_pdf = os.path.join(desktop_dir, 'Figure_8_4_1_Test_Cases_By_Module.pdf')
        try:
            shutil.copy2(png_path, dt_png)
            shutil.copy2(pdf_path, dt_pdf)
            print(f"[OK] Copied to Desktop: {dt_png}")
            print(f"[OK] Copied to Desktop: {dt_pdf}")
        except Exception as e:
            print(f"[WARN] Desktop copy: {e}")

if __name__ == '__main__':
    generate_test_cases_by_module_plot()

