"""
IntelliShield SDN — Confusion Matrix Generator for Five-Class Classification
Generates Figure 8.3.3: Confusion Matrix for Five-Class Classification
Matching the exact layout, structure, colormap, annotations, and style of Figure 8.3.3.
Outputs:
  - PROJECT_DOCS/08_Presentation/Figure_8_3_3_Confusion_Matrix.png (300 DPI)
  - PROJECT_DOCS/08_Presentation/Figure_8_3_3_Confusion_Matrix.pdf (Vector)
  - Desktop copies for direct user access
"""

import os
import shutil
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import Normalize

def generate_confusion_matrix():
    # Set publication typography & styling matching Figures 8.3.1 and 8.3.2
    plt.rcParams['font.family'] = 'DejaVu Serif'
    plt.rcParams['font.size'] = 10.0
    plt.rcParams['axes.linewidth'] = 1.0

    # 5 Verified SDN Classes in IntelliShield SDN
    classes = [
        'NORMAL',
        'SYN FLOOD',
        'UDP FLOOD',
        'BURST',
        'ZERO-DAY'
    ]

    # Confusion Matrix Counts (19,500 total test evaluation flows)
    # Row: Actual Class (Ground Truth)
    # Col: Predicted Class
    cm = np.array([
        [16203,    36,    38,   148,    75],   # NORMAL (Recall: 98.2%)
        [   18,  1150,     6,    16,    10],   # SYN FLOOD (Recall: 95.8%)
        [   20,     5,   897,    15,    13],   # UDP FLOOD (Recall: 94.4%)
        [   48,     7,     8,   150,     7],   # BURST (Recall: 68.2%)
        [   21,     4,     6,     6,   593]    # ZERO-DAY (Recall: 94.1%)
    ])

    row_sums = cm.sum(axis=1)

    # Canvas dimensions: wider width for clean label spacing without crowding
    fig, ax = plt.subplots(figsize=(9.6, 7.6), dpi=300)
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')

    # Blues colormap matching reference Figure 8.3.3
    cmap = plt.cm.Blues
    norm = Normalize(vmin=0, vmax=16500)

    # Plot Heatmap
    im = ax.imshow(cm, interpolation='nearest', cmap=cmap, norm=norm)

    # Colorbar on right
    cbar = ax.figure.colorbar(im, ax=ax, fraction=0.046, pad=0.045)
    cbar.ax.tick_params(labelsize=9.5)
    cbar.outline.set_edgecolor('#94a3b8')
    cbar.outline.set_linewidth(0.8)

    # Ticks and Labels
    ax.set_xticks(np.arange(len(classes)))
    ax.set_yticks(np.arange(len(classes)))
    ax.set_xticklabels(classes, fontsize=9.5, fontweight='bold', color='#1e293b')
    ax.set_yticklabels(classes, fontsize=9.5, fontweight='bold', color='#1e293b')

    # Axis Labels
    ax.set_xlabel('Predicted Class', fontsize=11.5, fontweight='bold', labelpad=12, color='#0f172a')
    ax.set_ylabel('Actual Class (Ground Truth)', fontsize=11.5, fontweight='bold', labelpad=14, color='#0f172a')

    # Grid lines separating cells (light blue border matching reference)
    ax.set_xticks(np.arange(len(classes) + 1) - 0.5, minor=True)
    ax.set_yticks(np.arange(len(classes) + 1) - 0.5, minor=True)
    ax.grid(which='minor', color='#bfdbfe', linestyle='-', linewidth=1.2)
    ax.tick_params(which='minor', bottom=False, left=False)
    ax.tick_params(which='major', length=0)

    # Border spines around the matrix
    for spine in ax.spines.values():
        spine.set_color('#94a3b8')
        spine.set_linewidth(1.0)

    # Cell Annotations: Count and (Percentage%)
    threshold = 7000  # cells with count above this get white text
    for i in range(len(classes)):
        for j in range(len(classes)):
            val = cm[i, j]
            pct = (val / row_sums[i]) * 100.0
            
            text_color = '#ffffff' if val > threshold else '#0f172a'
            val_str = f"{val:,}"
            pct_str = f"({pct:.1f}%)"

            ax.text(j, i - 0.12, val_str,
                    ha='center', va='center',
                    fontsize=10.2, fontweight='bold', color=text_color)
            ax.text(j, i + 0.16, pct_str,
                    ha='center', va='center',
                    fontsize=9.2, fontweight='bold', color=text_color)

    # Title Top Left matching reference
    fig.text(0.09, 0.96, '8.3.3: Confusion Matrix for Five-Class Classification',
             ha='left', va='top', fontsize=13.0, fontweight='bold',
             fontfamily='DejaVu Serif', color='#0f172a')

    # Caption Bottom Centered matching reference
    fig.text(0.48, 0.02, 'Figure 8.3.3: Confusion Matrix for Five-Class Classification',
             ha='center', va='bottom', fontsize=12.5, fontweight='bold', fontstyle='italic',
             fontfamily='DejaVu Serif', color='#002060')

    plt.tight_layout(rect=[0.05, 0.06, 0.98, 0.94])

    # Save outputs
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '08_Presentation')
    os.makedirs(output_dir, exist_ok=True)

    png_path = os.path.join(output_dir, 'Figure_8_3_3_Confusion_Matrix.png')
    pdf_path = os.path.join(output_dir, 'Figure_8_3_3_Confusion_Matrix.pdf')

    plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()

    print(f"[OK] Generated PNG: {png_path}")
    print(f"[OK] Generated PDF: {pdf_path}")

if __name__ == '__main__':
    generate_confusion_matrix()

