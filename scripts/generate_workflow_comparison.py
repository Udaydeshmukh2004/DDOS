#!/usr/bin/env python3
"""
Generate publication-quality Workflow Stage Time Comparison Graph for IntelliShield SDN.
Faithfully reproduces the visual design, markers, line weights, gridlines, and typography
of the user's reference image while tailoring the stages to IntelliShield SDN.

Outputs:
  - docs/architecture/intellishield_workflow_comparison.png (High-Res 300 DPI)
  - docs/architecture/intellishield_workflow_comparison.svg (Vector graphics)
  - Copies to Windows Desktop and Brain artifact directory for instant viewing
"""

import os
import shutil
import matplotlib.pyplot as plt

# Output paths
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS_DIR = os.path.join(ROOT, "docs", "architecture")
STATIC_DIR = os.path.join(ROOT, "dashboard", "static")
os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

PNG_NAME = "intellishield_workflow_comparison.png"
SVG_NAME = "intellishield_workflow_comparison.svg"

OUT_PNG = os.path.join(DOCS_DIR, PNG_NAME)
OUT_SVG = os.path.join(DOCS_DIR, SVG_NAME)

STATIC_PNG = os.path.join(STATIC_DIR, PNG_NAME)
STATIC_SVG = os.path.join(STATIC_DIR, SVG_NAME)

DESKTOP_DIR = "/mnt/c/Users/deshm/OneDrive/Desktop"
BRAIN_DIR = "/mnt/c/Users/deshm/.gemini/antigravity/brain/f4598107-5979-4f10-b0aa-450d9f55e8db"


def plot_workflow_comparison(unit="Minutes"):
    """
    Generate graph comparing Existing SDN incident workflow vs IntelliShield SDN.
    """
    stages = [
        "Traffic\nmonitoring",
        "Feature\nextraction",
        "Attack\ndetection",
        "Alert\ncorrelation",
        "Mitigation\nenforcement",
    ]

    # Data points matching the characteristic trajectory of the reference image:
    # Existing baseline exhibits dramatic peak during analysis/detection & correlation.
    # IntelliShield maintains flat, sub-5-minute autonomous response across all stages.
    existing_time = [2.0, 8.0, 20.0, 15.0, 12.0]
    intellishield_time = [1.0, 2.0, 3.0, 3.0, 5.0]

    fig, ax = plt.subplots(figsize=(10, 5.0), dpi=300)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    # Dashed horizontal gridlines matching reference
    ax.yaxis.grid(True, linestyle="--", color="#d1d5db", linewidth=0.85, zorder=1)
    ax.xaxis.grid(False)

    # Plot Series 1: Existing (min) - Slate Gray line with Teal square markers
    ax.plot(
        stages,
        existing_time,
        color="#70757a",
        linewidth=3.2,
        marker="s",
        markersize=9.5,
        markerfacecolor="#528a90",
        markeredgecolor="#374151",
        markeredgewidth=1.8,
        label=f"Existing SDN ({'min' if unit == 'Minutes' else 's'})",
        zorder=3,
    )

    # Plot Series 2: IntelliShield (min) - Royal Blue line with Orange-bordered circular markers
    ax.plot(
        stages,
        intellishield_time,
        color="#2253b8",
        linewidth=3.2,
        marker="o",
        markersize=9.5,
        markerfacecolor="#2253b8",
        markeredgecolor="#ea580c",
        markeredgewidth=2.2,
        label=f"IntelliShield SDN ({'min' if unit == 'Minutes' else 's'})",
        zorder=4,
    )

    # Y-axis configuration
    ax.set_ylim(0, 25)
    ax.set_yticks([0, 5, 10, 15, 20, 25])
    ax.set_ylabel(unit, fontsize=12, fontweight="bold", labelpad=12, color="#000000")
    ax.tick_params(axis="y", labelsize=11, colors="#000000", length=4, width=1.0)

    # X-axis configuration
    ax.set_xlabel("Workflow stage", fontsize=12, fontweight="bold", labelpad=12, color="#000000")
    ax.tick_params(axis="x", labelsize=10.5, colors="#000000", length=4, width=1.0)

    # Frame / Spines: Thin border matching reference style
    for spine in ["top", "right"]:
        ax.spines[spine].set_color("#e5e7eb")
        ax.spines[spine].set_linewidth(0.8)
    for spine in ["left", "bottom"]:
        ax.spines[spine].set_color("#000000")
        ax.spines[spine].set_linewidth(1.2)

    # Legend at bottom center matching reference layout
    legend = ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.22),
        ncol=2,
        frameon=False,
        fontsize=11.5,
        handlelength=2.5,
        handletextpad=0.6,
        columnspacing=2.5,
    )
    for text in legend.get_texts():
        text.set_color("#000000")

    plt.tight_layout()
    plt.savefig(OUT_PNG, dpi=300, bbox_inches="tight", facecolor="white")
    plt.savefig(OUT_SVG, format="svg", bbox_inches="tight", facecolor="white")
    plt.close()

    print(f"Saved: {OUT_PNG}")
    print(f"Saved: {OUT_SVG}")

    # Copy to static web assets
    try:
        shutil.copyfile(OUT_PNG, STATIC_PNG)
        shutil.copyfile(OUT_SVG, STATIC_SVG)
        print(f"Copied to static: {STATIC_PNG}")
    except Exception as e:
        print(f"Static copy warning: {e}")

    # Copy to Desktop
    if os.path.isdir(DESKTOP_DIR):
        try:
            shutil.copyfile(OUT_PNG, os.path.join(DESKTOP_DIR, PNG_NAME))
            shutil.copyfile(OUT_SVG, os.path.join(DESKTOP_DIR, SVG_NAME))
            print(f"Copied to Desktop: {DESKTOP_DIR}/{PNG_NAME}")
        except Exception as e:
            print(f"Desktop copy warning: {e}")

    # Copy to Brain Artifact dir
    if os.path.isdir(BRAIN_DIR):
        try:
            shutil.copyfile(OUT_PNG, os.path.join(BRAIN_DIR, PNG_NAME))
            shutil.copyfile(OUT_SVG, os.path.join(BRAIN_DIR, SVG_NAME))
            print(f"Copied to Brain Artifacts: {BRAIN_DIR}/{PNG_NAME}")
        except Exception as e:
            print(f"Brain copy warning: {e}")


if __name__ == "__main__":
    plot_workflow_comparison(unit="Minutes")

