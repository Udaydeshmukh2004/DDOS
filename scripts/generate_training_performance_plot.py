"""
IntelliShield SDN — Training and Validation Performance Plot Generator
Generates Figure 8.4.3: Training and validation performance.
Dual-panel plot:
  (a) Training vs Validation Accuracy
  (b) Training vs Validation Loss
Matching the exact layout, curves, markers, shaded regions, annotations, and typography of Figure 8.4.3.
Outputs:
  - PROJECT_DOCS/08_Presentation/Figure_8_4_3_Training_Validation_Performance.png (300 DPI)
  - PROJECT_DOCS/08_Presentation/Figure_8_4_3_Training_Validation_Performance.pdf (Vector)
  - Desktop copies for direct user access
"""

import os
import shutil
import numpy as np
import matplotlib.pyplot as plt

def generate_training_performance_plot():
    # Set high-quality serif typography matching dissertation chapters
    plt.rcParams['font.family'] = 'DejaVu Serif'
    plt.rcParams['font.size'] = 10.0
    plt.rcParams['axes.linewidth'] = 1.0

    epochs = np.arange(1, 11)

    # ─── Data Definitions (Matching Figure 8.4.3 Reference) ───────────────────
    # Subplot (a) Accuracy (%)
    train_acc = [86.1, 95.7, 97.0, 97.6, 97.3, 97.8, 97.8, 98.1, 98.5, 98.3]
    val_acc   = [96.8, 98.0, 99.1, 98.8, 99.0, 99.0, 99.1, 99.1, 99.3, 99.2]
    held_out_acc = 92.59  # Matches Figure 8.3.1 overall test accuracy

    # Subplot (b) Loss
    train_loss = [0.57, 0.28, 0.21, 0.18, 0.19, 0.15, 0.13, 0.11, 0.10, 0.09]
    val_loss   = [0.15, 0.08, 0.05, 0.06, 0.05, 0.05, 0.04, 0.04, 0.03, 0.03]
    held_out_loss = 0.427

    # Canvas dimensions matching Figure 8.4.3
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.4, 5.8), dpi=300)
    fig.patch.set_facecolor('white')

    # Color definitions matching reference
    color_train = '#2563eb'     # Vibrant Blue
    color_val   = '#dc2626'     # Bold Crimson Red
    color_test  = '#059669'     # Forest Green for test benchmark line
    fill_acc    = '#e0f2fe'     # Light Sky Blue fill
    fill_loss   = '#fee2e2'     # Light Soft Red fill

    # ═════════════════════════════════════════════════════════════════════════
    # SUBPLOT (a): Training vs Validation Accuracy
    # ═════════════════════════════════════════════════════════════════════════
    ax1.set_facecolor('white')

    # Shaded region between curves
    ax1.fill_between(epochs, train_acc, val_acc, color=fill_acc, alpha=0.6, zorder=2)

    # Held-out test reference line
    ax1.axhline(y=held_out_acc, color=color_test, linestyle=':', linewidth=1.8,
                label=f'Held-Out Test ({held_out_acc}%)', zorder=3)

    # Curves
    ax1.plot(epochs, train_acc, color=color_train, marker='o', markersize=5.5,
             linewidth=1.8, label='Training Accuracy', zorder=4)
    ax1.plot(epochs, val_acc, color=color_val, marker='s', markersize=5.5,
             linestyle='--', linewidth=1.8, label='Validation Accuracy', zorder=4)

    # Value annotations on (a)
    for i, ep in enumerate(epochs):
        # Validation accuracy (Red, above point)
        va = val_acc[i]
        offset_y = 0.35 if ep != 4 else 0.40
        ax1.annotate(f'{va:.1f}%', xy=(ep, va), xytext=(0, 5), textcoords="offset points",
                     ha='center', va='bottom', fontsize=8.0, fontweight='bold', color=color_val)

        # Training accuracy (Blue, below/above based on overlap)
        ta = train_acc[i]
        va_offset = -12 if ep not in [1, 2] else 6
        ax1.annotate(f'{ta:.1f}%', xy=(ep, ta), xytext=(0, va_offset), textcoords="offset points",
                     ha='center', va='top' if va_offset < 0 else 'bottom',
                     fontsize=8.0, fontweight='bold', color=color_train)

    ax1.set_title('(a) Training vs Validation Accuracy', fontsize=11.5, fontweight='bold', pad=12)
    ax1.set_xlabel('Epoch', fontsize=10.5, fontweight='bold', labelpad=8)
    ax1.set_ylabel('Accuracy (%)', fontsize=10.5, fontweight='bold', labelpad=8)
    ax1.set_xlim(0.6, 10.4)
    ax1.set_xticks(epochs)
    ax1.set_ylim(82.0, 101.5)
    ax1.set_yticks([82.5, 85.0, 87.5, 90.0, 92.5, 95.0, 97.5, 100.0])
    ax1.set_yticklabels(['82.5%', '85.0%', '87.5%', '90.0%', '92.5%', '95.0%', '97.5%', '100.0%'], fontsize=9.2)

    ax1.grid(axis='y', linestyle='--', alpha=0.5, color='#cbd5e1', zorder=0)
    ax1.set_axisbelow(True)
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    ax1.spines['left'].set_color('#334155')
    ax1.spines['bottom'].set_color('#334155')

    legend1 = ax1.legend(loc='lower right', frameon=True, framealpha=0.95,
                         edgecolor='#cbd5e1', fontsize=8.5)
    legend1.get_frame().set_linewidth(0.8)

    # ═════════════════════════════════════════════════════════════════════════
    # SUBPLOT (b): Training vs Validation Loss
    # ═════════════════════════════════════════════════════════════════════════
    ax2.set_facecolor('white')

    # Shaded region between curves
    ax2.fill_between(epochs, train_loss, val_loss, color=fill_loss, alpha=0.6, zorder=2)

    # Held-out test reference line
    ax2.axhline(y=held_out_loss, color=color_test, linestyle=':', linewidth=1.8,
                label=f'Test Loss ({held_out_loss})', zorder=3)

    # Curves
    ax2.plot(epochs, train_loss, color=color_train, marker='o', markersize=5.5,
             linewidth=1.8, label='Training Loss', zorder=4)
    ax2.plot(epochs, val_loss, color=color_val, marker='s', markersize=5.5,
             linestyle='--', linewidth=1.8, label='Validation Loss', zorder=4)

    # Value annotations on (b)
    for i, ep in enumerate(epochs):
        # Training loss (Blue, above point)
        tl = train_loss[i]
        ax2.annotate(f'{tl:.2f}', xy=(ep, tl), xytext=(0, 5), textcoords="offset points",
                     ha='center', va='bottom', fontsize=8.0, fontweight='bold', color=color_train)

        # Validation loss (Red, below point)
        vl = val_loss[i]
        ax2.annotate(f'{vl:.2f}', xy=(ep, vl), xytext=(0, -12), textcoords="offset points",
                     ha='center', va='top', fontsize=8.0, fontweight='bold', color=color_val)

    ax2.set_title('(b) Training vs Validation Loss', fontsize=11.5, fontweight='bold', pad=12)
    ax2.set_xlabel('Epoch', fontsize=10.5, fontweight='bold', labelpad=8)
    ax2.set_ylabel('Sparse Categorical Cross-Entropy Loss', fontsize=10.0, fontweight='bold', labelpad=8)
    ax2.set_xlim(0.6, 10.4)
    ax2.set_xticks(epochs)
    ax2.set_ylim(-0.02, 0.65)
    ax2.set_yticks([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6])
    ax2.set_yticklabels(['0.0', '0.1', '0.2', '0.3', '0.4', '0.5', '0.6'], fontsize=9.2)

    ax2.grid(axis='y', linestyle='--', alpha=0.5, color='#cbd5e1', zorder=0)
    ax2.set_axisbelow(True)
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    ax2.spines['left'].set_color('#334155')
    ax2.spines['bottom'].set_color('#334155')

    legend2 = ax2.legend(loc='upper right', frameon=True, framealpha=0.95,
                         edgecolor='#cbd5e1', fontsize=8.5)
    legend2.get_frame().set_linewidth(0.8)

    # Section Header Top Left matching reference
    fig.text(0.06, 0.96, '8.4.3: Training and validation performance.',
             ha='left', va='top', fontsize=13.5, fontweight='bold',
             fontfamily='DejaVu Serif', color='#0f172a')

    # Caption Bottom Centered matching reference
    fig.text(0.50, 0.02, 'Figure 8.4.3: Training and validation performance.',
             ha='center', va='bottom', fontsize=12.5, fontweight='bold', fontstyle='italic',
             fontfamily='DejaVu Serif', color='#002060')

    plt.tight_layout(rect=[0.02, 0.06, 0.98, 0.92])

    # Save outputs
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '08_Presentation')
    os.makedirs(output_dir, exist_ok=True)

    png_path = os.path.join(output_dir, 'Figure_8_4_3_Training_Validation_Performance.png')
    pdf_path = os.path.join(output_dir, 'Figure_8_4_3_Training_Validation_Performance.pdf')

    plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()

    print(f"[OK] Generated PNG: {png_path}")
    print(f"[OK] Generated PDF: {pdf_path}")

    # Copy to Desktop
    desktop_dir = r"C:\Users\deshm\OneDrive\Desktop"
    if os.path.exists(desktop_dir):
        dt_png = os.path.join(desktop_dir, 'Figure_8_4_3_Training_Validation_Performance.png')
        dt_pdf = os.path.join(desktop_dir, 'Figure_8_4_3_Training_Validation_Performance.pdf')
        try:
            shutil.copy2(png_path, dt_png)
            shutil.copy2(pdf_path, dt_pdf)
            print(f"[OK] Copied to Desktop: {dt_png}")
            print(f"[OK] Copied to Desktop: {dt_pdf}")
        except Exception as e:
            print(f"[WARN] Desktop copy: {e}")

if __name__ == '__main__':
    generate_training_performance_plot()

