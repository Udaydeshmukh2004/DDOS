"""
IntelliShield SDN — Publication-Quality Result Comparison Chart Generator
Generates Figure 8.3.1: Overall Classification Performance Metrics
Matching IEEE / MCA Dissertation report formatting.
"""

import os
import matplotlib.pyplot as plt
import numpy as np

# Set high-quality font and rendering settings
plt.rcParams['font.family'] = 'DejaVu Serif'
plt.rcParams['font.size'] = 11
plt.rcParams['axes.linewidth'] = 1.0

# ─── Data Definitions ──────────────────────────────────────────────────────────
metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
weighted_avg = [92.59, 97.14, 92.59, 94.32]
macro_avg    = [92.59, 58.23, 89.43, 65.93]

x = np.arange(len(metrics))  # label locations
width = 0.35                 # width of the bars

# ─── Figure Canvas Setup ──────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(8.5, 5.2), dpi=300)
fig.patch.set_facecolor('white')
ax.set_facecolor('white')

# ─── Colors matching academic presentation ────────────────────────────────────
# Dark royal blue for Weighted Average, Soft cornflower/sky blue for Macro Average
color_weighted = '#1d4ed8'   # Dark Blue
border_weighted = '#1e3a8a'
color_macro = '#93c5fd'      # Light Blue
border_macro = '#3b82f6'

# ─── Plot Bars ────────────────────────────────────────────────────────────────
rects1 = ax.bar(x - width/2, weighted_avg, width,
                label='Weighted Average',
                color=color_weighted, edgecolor=border_weighted, linewidth=1.2)
rects2 = ax.bar(x + width/2, macro_avg, width,
                label='Macro Average',
                color=color_macro, edgecolor=border_macro, linewidth=1.2)

# ─── Value Labels on Top of Bars ──────────────────────────────────────────────
def autolabel(rects, text_color):
    """Attach a text label above each bar in *rects*, displaying its value."""
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height:.2f}%',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 4),  # 4 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom',
                    fontsize=9.5, fontweight='bold',
                    color=text_color)

autolabel(rects1, '#1e3a8a')
autolabel(rects2, '#1e3a8a')

# ─── Axes, Spines, and Gridlines ─────────────────────────────────────────────
ax.set_ylabel('Score (%)', fontsize=11, fontweight='bold', labelpad=8)
ax.set_xticks(x)
ax.set_xticklabels(metrics, fontsize=11, color='#111827')
ax.set_ylim(0, 115)
ax.set_yticks([0, 20, 40, 60, 80, 100])
ax.set_yticklabels(['0%', '20%', '40%', '60%', '80%', '100%'], fontsize=10.5)

# Horizontal dashed gridlines only
ax.grid(axis='y', linestyle='--', alpha=0.5, color='#cbd5e1', zorder=0)
ax.set_axisbelow(True)

# Clean academic spines: show left & bottom, hide top & right
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_color('#334155')
ax.spines['bottom'].set_color('#334155')

# ─── Legend Configuration ─────────────────────────────────────────────────────
legend = ax.legend(loc='lower right', frameon=True, framealpha=0.95,
                   edgecolor='#94a3b8', fontsize=10.5)
legend.get_frame().set_linewidth(1.0)

# ─── Section Header & Figure Caption ──────────────────────────────────────────
# Subtitle & Section Header at top
fig.text(0.08, 0.96, '8.3 Result Comparison',
         fontsize=14, fontweight='bold', fontfamily='DejaVu Serif', color='#0f172a')
fig.text(0.08, 0.90, '8.3.1: Overall Classification Performance Metrics',
         fontsize=12, fontweight='bold', fontfamily='DejaVu Serif', color='#0f172a')

# Figure caption below the plot
fig.text(0.50, 0.02, 'Figure 8.3.1: Overall Classification Performance Metrics',
         ha='center', fontsize=11, fontstyle='italic', fontweight='bold',
         fontfamily='DejaVu Serif', color='#0f172a')

plt.subplots_adjust(top=0.86, bottom=0.14, left=0.12, right=0.95)

# ─── Save Outputs ─────────────────────────────────────────────────────────────
output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '06_Results')
os.makedirs(output_dir, exist_ok=True)

png_path = os.path.join(output_dir, 'Figure_8_3_1_Overall_Classification_Performance_Metrics.png')
pdf_path = os.path.join(output_dir, 'Figure_8_3_1_Overall_Classification_Performance_Metrics.pdf')

plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
plt.close()

print(f"Successfully generated:")
print(f"  PNG: {png_path}")
print(f"  PDF: {pdf_path}")

