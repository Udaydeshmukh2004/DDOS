"""
IntelliShield SDN — Class-Wise Attack Detection Performance Chart Generator
Generates Figure 8.3.2: Class-Wise Attack Detection Performance (Precision, Recall, F1-Score)
for MCA Dissertation / IEEE Research Paper.
"""

import os
import matplotlib.pyplot as plt
import numpy as np

# Set publication typography & styling
plt.rcParams['font.family'] = 'DejaVu Serif'
plt.rcParams['font.size'] = 10.5
plt.rcParams['axes.linewidth'] = 1.0

# ─── Data Definitions (IntelliShield SDN Scenarios) ───────────────────────────
classes = [
    'Normal Traffic\n(NORMAL)',
    'TCP SYN Flood\n(SYN_FLOOD)',
    'UDP Flood\n(UDP_FLOOD)',
    'Burst Attack\n(BURST_FLOOD)',
    'Zero-Day Flood\n(ZERO_DAY_SSL)',
]

# Order matching Figure 8.3.2: Precision (Blue), F1-Score (Green), Recall (Orange)
precision = [99.2, 96.5, 95.2, 55.4, 91.6]
f1_score  = [98.7, 96.2, 94.8, 61.1, 92.8]
recall    = [98.2, 95.8, 94.4, 68.2, 94.1]

x = np.arange(len(classes))  # label locations
width = 0.22                 # width of the bars

# ─── Figure Canvas Setup ──────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(10.5, 5.8), dpi=300)
fig.patch.set_facecolor('white')
ax.set_facecolor('white')

# ─── Colors matching Figure 8.3.2 Reference ──────────────────────────────────
# Precision (Blue), F1-Score (Teal/Green), Recall (Orange/Amber)
color_prec = '#3b82f6'    # Blue
border_prec = '#1d4ed8'
color_f1   = '#059669'    # Teal Green
border_f1   = '#047857'
color_rec  = '#ea580c'    # Orange Amber
border_rec = '#c2410c'

# ─── Plot Bars ────────────────────────────────────────────────────────────────
# Bar order in each group: Precision, F1-Score, Recall
rects_prec = ax.bar(x - width, precision, width,
                    label='Precision',
                    color=color_prec, edgecolor=border_prec, linewidth=1.1, zorder=3)
rects_f1   = ax.bar(x, f1_score, width,
                    label='F1-Score',
                    color=color_f1, edgecolor=border_f1, linewidth=1.1, zorder=3)
rects_rec  = ax.bar(x + width, recall, width,
                    label='Recall',
                    color=color_rec, edgecolor=border_rec, linewidth=1.1, zorder=3)

# ─── Value Labels on Top of Bars ──────────────────────────────────────────────
def autolabel(rects, text_color):
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height:.1f}%',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 4),  # 4 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom',
                    fontsize=8.5, fontweight='bold',
                    color=text_color)

autolabel(rects_prec, '#1e3a8a')
autolabel(rects_f1,   '#065f46')
autolabel(rects_rec,  '#9a3412')

# ─── Axes, Spines, and Gridlines ─────────────────────────────────────────────
ax.set_ylabel('Metric Score (%)', fontsize=11, fontweight='bold', labelpad=8)
ax.set_xticks(x)
ax.set_xticklabels(classes, fontsize=10, fontweight='bold', color='#1e293b')
ax.set_ylim(0, 115)
ax.set_yticks([0, 20, 40, 60, 80, 100])
ax.set_yticklabels(['0%', '20%', '40%', '60%', '80%', '100%'], fontsize=10)

# Horizontal dashed gridlines only
ax.grid(axis='y', linestyle='--', alpha=0.5, color='#cbd5e1', zorder=0)
ax.set_axisbelow(True)

# Clean academic spines
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.spines['left'].set_color('#334155')
ax.spines['bottom'].set_color('#334155')

# ─── Legend Configuration (Top Right) ─────────────────────────────────────────
# Order in legend matching reference: F1-Score (green), Precision (blue), Recall (orange)
handles = [rects_f1, rects_prec, rects_rec]
labels  = ['F1-Score', 'Precision', 'Recall']
legend = ax.legend(handles, labels, loc='upper right', frameon=True, framealpha=0.95,
                   edgecolor='#94a3b8', fontsize=10)
legend.get_frame().set_linewidth(1.0)

# ─── Headings and Figure Caption ──────────────────────────────────────────────
fig.text(0.06, 0.96, '8.3.2: Class-Wise Attack Detection Performance',
         fontsize=14, fontweight='bold', fontfamily='DejaVu Serif', color='#0f172a')
fig.text(0.50, 0.90, 'Figure 8.3.2 — Per-Class Detection Performance (Precision, Recall, F1-Score)',
         ha='center', fontsize=11.5, fontweight='bold', fontfamily='DejaVu Serif', color='#0f172a')

fig.text(0.50, 0.02, 'Figure 8.3.2: Class-Wise Attack Detection Performance',
         ha='center', fontsize=11, fontstyle='italic', fontweight='bold',
         fontfamily='DejaVu Serif', color='#0f172a')

plt.subplots_adjust(top=0.86, bottom=0.15, left=0.08, right=0.96)

# ─── Save Outputs ─────────────────────────────────────────────────────────────
output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'PROJECT_DOCS', '06_Results')
os.makedirs(output_dir, exist_ok=True)

png_path = os.path.join(output_dir, 'Figure_8_3_2_Class_Wise_Attack_Detection_Performance.png')
pdf_path = os.path.join(output_dir, 'Figure_8_3_2_Class_Wise_Attack_Detection_Performance.pdf')

plt.savefig(png_path, dpi=300, bbox_inches='tight', facecolor='white')
plt.savefig(pdf_path, dpi=300, bbox_inches='tight', facecolor='white')
plt.close()

print(f"Successfully generated:")
print(f"  PNG: {png_path}")
print(f"  PDF: {pdf_path}")

