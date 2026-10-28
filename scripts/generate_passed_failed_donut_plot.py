"""
IntelliShield SDN — Passed vs. Failed Test Cases Donut Chart Generator
Generates Figure 8.4.2: Passed vs. failed test cases.
Matching the exact layout, doughnut proportions, emerald green color, center text, and typography of Figure 8.4.2.
Outputs:
  - PROJECT_DOCS/08_Presentation/Figure_8_4_2_Passed_Vs_Failed_Test_Cases.png (300 DPI)
  - PROJECT_DOCS/08_Presentation/Figure_8_4_2_Passed_Vs_Failed_Test_Cases.pdf (Vector)
  - Desktop copies for direct user access
"""

import os
import shutil
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

def generate_passed_failed_donut_plot():
    # Set high-quality serif typography matching dissertation chapters
    plt.rcParams['font.family'] = 'DejaVu Serif'
    plt.rcParams['font.size'] = 10.0
    plt.rcParams['axes.linewidth'] = 1.0

    total_tests = 46
    passed_tests = 46
    failed_tests = 0

    # Canvas dimensions matching Figure 8.4.2
    fig, ax = plt.subplots(figsize=(8.2, 6.6), dpi=300)
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')

    # Color definitions matching Figure 8.4.2 reference
    color_pass = '#16a34a'       # Vibrant Emerald Green
    border_pass = '#15803d'

    # Donut Chart Wedges: 100% Passed
    wedges, texts = ax.pie([passed_tests],
                           colors=[color_pass],
                           startangle=90,
                           wedgeprops=dict(width=0.45, edgecolor=border_pass, linewidth=1.2))

    # Center circle for clean donut hole
    # Text in center hole (4 lines matching reference)
    center_text = "Total\n46\nTests\n100% Pass"
    ax.text(0, 0, center_text,
            ha='center', va='center',
            fontsize=11.2, fontweight='bold', fontfamily='DejaVu Sans',
            color='#166534', linespacing=1.25)

    # "100.0%" text placed inside the bottom arc of the green ring
    # Angle 270 deg (bottom): radius ~0.78
    ax.text(0, -0.74, '100.0%',
            ha='center', va='center',
            fontsize=12.5, fontweight='bold', fontfamily='DejaVu Sans',
            color='#ffffff')

    ax.axis('equal')

    # Title Top Left matching reference
    fig.text(0.08, 0.94, '8.4.2: Passed vs. failed test cases',
             ha='left', va='top', fontsize=13.0, fontweight='bold',
             fontfamily='DejaVu Serif', color='#0f172a')

    # Label below donut matching reference
    fig.text(0.50, 0.22, 'Passed Test Cases',
             ha='center', va='center', fontsize=11.0, fontweight='bold',
             fontfamily='DejaVu Sans', color='#0f172a')

    # Custom rounded legend box below label matching reference
    legend_elements = [
        Patch(facecolor=color_pass, edgecolor=border_pass, label=f'Passed: {passed_tests} (100.0%)')
    ]
    legend = ax.legend(handles=legend_elements, loc='lower center', bbox_to_anchor=(0.50, -0.16),
                       frameon=True, framealpha=0.95, edgecolor='#cbd5e1', fontsize=9.6)
    legend.get_frame().set_linewidth(0.8)

    # Caption Bottom Centered matching reference
    fig.text(0.50, 0.03, 'Figure 8.4.2: Passed vs. failed test cases.',
             ha='center', va='bottom', fontsize=12.5, fontweight='bold', fontstyle='italic',
             fontfamily='DejaVu Serif', color='#002060')

    plt.tight_layout(rect=[0.05, 0.08, 0.95, 0.92])

    # Save outputs
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '08_Presentation')
    os.makedirs(output_dir, exist_ok=True)

    png_path = os.path.join(output_dir, 'Figure_8_4_2_Passed_Vs_Failed_Test_Cases.png')
    pdf_path = os.path.join(output_dir, 'Figure_8_4_2_Passed_Vs_Failed_Test_Cases.pdf')

    plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()

    print(f"[OK] Generated PNG: {png_path}")
    print(f"[OK] Generated PDF: {pdf_path}")

    # Copy to Desktop
    desktop_dir = r"C:\Users\deshm\OneDrive\Desktop"
    if os.path.exists(desktop_dir):
        dt_png = os.path.join(desktop_dir, 'Figure_8_4_2_Passed_Vs_Failed_Test_Cases.png')
        dt_pdf = os.path.join(desktop_dir, 'Figure_8_4_2_Passed_Vs_Failed_Test_Cases.pdf')
        try:
            shutil.copy2(png_path, dt_png)
            shutil.copy2(pdf_path, dt_pdf)
            print(f"[OK] Copied to Desktop: {dt_png}")
            print(f"[OK] Copied to Desktop: {dt_pdf}")
        except Exception as e:
            print(f"[WARN] Desktop copy: {e}")

if __name__ == '__main__':
    generate_passed_failed_donut_plot()

