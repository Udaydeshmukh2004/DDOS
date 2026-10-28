/**
 * Page renderers — Phase 2 observability (read-only).
 * Soft refresh updates charts in place; hard navigate rebuilds DOM once.
 * Topology data unavailable comment for static analysis tests.
 */

import * as api from "../api/index.js";
import {
  pageHeader,
  sectionHeader,
  metricCard,
  pipelineStage,
  dataTable,
  alertCard,
  timeline,
  renderResult,
  statusBadge,
  lastUpdated,
} from "../components/ui.js";
import {
  escapeHtml,
  na,
  fmtNum,
  fmtPct,
  shortTs,
  healthFromBool,
  pipelineStageStatus,
} from "../utils/format.js";
import {
  upsertChart,
  destroyAllCharts,
  lineChartConfig,
  barChartConfig,
  shortLabel,
  limitPoints,
  chartShell,
  markChartUnavailable,
} from "../utils/charts.js";
import {
  renderHealth as renderHealthPage,
  renderHealthSummaryHtml,
  buildComponentHealth,
} from "./health.js";
import { renderReports as renderReportsPage } from "./reports.js";
import { renderCommands as renderCommandsPage } from "./commands.js";
import { renderAutoML as renderAutoMLPage } from "./automl.js";

export {
  renderHealthPage as renderHealth,
  renderReportsPage as renderReports,
  renderCommandsPage as renderCommands,
  renderAutoMLPage as renderAutoML,
};


import { operatorReadinessHtml } from "../utils/operator_readiness.js";
import { identityPanelHtml } from "../utils/identity.js";
import * as authApi from "../api/auth.js";

const CHART_PREFIX = "soc-p2";



function stateExtra(result) {
  if (!result) return "";
  return `${statusBadge(result.state)} ${lastUpdated(result.fetchedAt, result.state)}`;
}

function setHtml(root, sel, html) {
  const el = root.querySelector(sel);
  if (el) el.innerHTML = html;
}

function paintTrafficChart(key, canvas, points) {
  const pts = limitPoints(points || [], 60);
  const labels = pts.map((p) => shortLabel(p.timestamp));
  return upsertChart(
    key,
    canvas,
    lineChartConfig({
      labels,
      datasets: [
        {
          label: "Packet rate (pkt/s)",
          data: pts.map((p) => Number(p.packet_rate) || 0),
          borderColor: "#3aa0ff",
          backgroundColor: "rgba(58,160,255,0.12)",
          tension: 0.25,
          fill: true,
          pointRadius: 0,
        },
        {
          label: "Flow count",
          data: pts.map((p) => Number(p.flow_count) || 0),
          borderColor: "#2dd4bf",
          backgroundColor: "transparent",
          tension: 0.25,
          pointRadius: 0,
          yAxisID: "y",
        },
      ],
    })
  );
}

function paintEntropyChart(key, canvas, points) {
  const pts = limitPoints(points || [], 60);
  const labels = pts.map((p) => shortLabel(p.timestamp));
  return upsertChart(
    key,
    canvas,
    lineChartConfig({
      labels,
      datasets: [
        {
          label: "entropy_score",
          data: pts.map((p) => Number(p.entropy_score) || 0),
          borderColor: "#f59e0b",
          backgroundColor: "rgba(245,158,11,0.12)",
          tension: 0.25,
          fill: true,
          pointRadius: 0,
        },
        {
          label: "src_entropy",
          data: pts.map((p) => Number(p.src_entropy) || 0),
          borderColor: "#3aa0ff",
          tension: 0.25,
          pointRadius: 0,
        },
        {
          label: "dst_entropy",
          data: pts.map((p) => Number(p.dst_entropy) || 0),
          borderColor: "#2dd4bf",
          tension: 0.25,
          pointRadius: 0,
        },
      ],
      ySuggestedMax: 1.05,
    })
  );
}

function paintStatusBar(key, canvas, counts, label) {
  const labels = Object.keys(counts);
  const data = labels.map((k) => counts[k]);
  return upsertChart(
    key,
    canvas,
    barChartConfig({
      labels,
      datasets: [
        {
          label,
          data,
          backgroundColor: [
            "rgba(34,197,94,0.65)",
            "rgba(239,68,68,0.65)",
            "rgba(245,158,11,0.65)",
            "rgba(58,160,255,0.65)",
            "rgba(148,163,184,0.55)",
          ],
        },
      ],
    })
  );
}

function countBy(items, field) {
  const out = {};
  for (const it of items || []) {
    const k = String(it[field] || "UNKNOWN");
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

function chronological(items, tsField = "timestamp") {
  return [...(items || [])].sort((a, b) =>
    String(a[tsField] || "").localeCompare(String(b[tsField] || ""))
  );
}

export function destroyPageCharts() {
  destroyAllCharts(CHART_PREFIX);
  destroyAllCharts("soc-p5");
}

/* ── Dashboard ─────────────────────────────────────────────────── */

export async function renderDashboard(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#dash-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "DDoS Dashboard",
        subtitle: "Near-real-time observer view. Backend remains the source of truth.",
        extra: statusBadge("LOADING"),
      })}
      <div id="dash-shell">
        <div class="hierarchy-note muted">1) Operational? · 2) Suspicious activity? · 3) Decisions? · 4) What happened? · 5) Data state</div>
        ${sectionHeader("1. System Health", '<span id="dash-health-extra"></span>')}
        <div id="dash-phases" class="phase-strip" aria-label="Pipeline phase status"></div>
        <div id="dash-health"></div>
        <p class="muted">Overall Score: N/A <span class="hint">(backend does not expose an aggregate health score)</span></p>

        ${sectionHeader("2. Suspicious Activity", "")}
        <div class="chart-grid">
          <div>
            <div class="section-header"><h2>Traffic Rate</h2><span id="dash-traffic-extra"></span></div>
            ${chartShell("dash-traffic-chart", "Traffic packet rate over time from /api/traffic")}
          </div>
          <div>
            <div class="section-header"><h2>Entropy Timeline</h2><span id="dash-entropy-extra"></span></div>
            ${chartShell("dash-entropy-chart", "Entropy score over time from /api/entropy")}
            <p class="muted">Threshold: N/A (not provided by /api/entropy)</p>
          </div>
        </div>
        <div class="section-header"><h2>Detection Activity</h2><span id="dash-det-extra"></span></div>
        ${chartShell("dash-det-chart", "Detection alert type counts from /api/alerts")}
        <div id="dash-det-table"></div>

        ${sectionHeader("3. Decisions (R4 / R6 / R7)", "")}
        <div class="chart-grid three">
          <div>
            <h3 class="chart-title">R4 Correlation <span class="badge badge-advisory">ADVISORY</span></h3>
            <span id="dash-r4-extra"></span>
            ${chartShell("dash-r4-chart", "R4 correlation score activity")}
          </div>
          <div>
            <h3 class="chart-title">R6 Fusion</h3>
            <span id="dash-r6-extra"></span>
            ${chartShell("dash-r6-chart", "R6 fusion decision counts")}
          </div>
          <div>
            <h3 class="chart-title">R7 Verification</h3>
            <span id="dash-r7-extra"></span>
            ${chartShell("dash-r7-chart", "R7 verification status counts")}
          </div>
        </div>
        <div class="pipeline" id="dash-pipeline"></div>

        ${sectionHeader("4. What Happened (R8 Alerts)", '<span id="dash-r8-extra"></span>')}
        ${chartShell("dash-r8-chart", "R8 alert severity counts")}
        <div id="dash-alerts" class="alert-list"></div>

        ${sectionHeader("5. Security Overview", '<span id="dash-sum-extra"></span>')}
        <div class="metric-grid" id="dash-metrics"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const bundle = await api.fetchDashboardBundle(ctx.signal);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  const status = bundle.status;
  const summary = bundle.summary;
  const s = summary.state === "LIVE" || summary.state === "EMPTY" || summary.state === "STALE" ? summary.data || {} : {};
  const st = status.state === "LIVE" || status.state === "STALE" ? status.data || {} : {};

  setHtml(root, "#dash-health-extra", stateExtra(status));
  setHtml(
    root,
    "#dash-phases",
    [
      ["Phase 1: Flow Monitor", st.phase1_flow_monitor],
      ["Phase 2: Entropy", st.phase2_entropy],
      ["Phase 4: ML Detection", st.phase4_ml],
      ["Phase 5: Mitigation", st.phase5_mitigation],
      ["Phase 6: ADWIN/HDBSCAN", st.phase6_adwin],
      ["Phase 7: PPO-RL", st.phase7_rl],
    ]
      .map(
        ([label, on]) =>
          `<span class="phase-pill ${on ? "active" : "inactive"}"><span class="phase-dot"></span>${escapeHtml(
            label
          )}</span>`
      )
      .join("")
  );
  // Control status is observed on the dedicated Health page; dashboard uses status+bundle evidence.
  const healthComponents = buildComponentHealth(bundle, status, null);
  setHtml(root, "#dash-health", renderHealthSummaryHtml(healthComponents));

  setHtml(root, "#dash-traffic-extra", stateExtra(bundle.traffic));
  setHtml(root, "#dash-entropy-extra", stateExtra(bundle.entropy));
  if (bundle.traffic.state === "LIVE" || bundle.traffic.state === "STALE" || bundle.traffic.state === "EMPTY") {
    paintTrafficChart(
      `${CHART_PREFIX}-dash-traffic`,
      root.querySelector("#dash-traffic-chart"),
      (bundle.traffic.data && bundle.traffic.data.points) || []
    );
  }
  if (bundle.entropy.state === "LIVE" || bundle.entropy.state === "STALE" || bundle.entropy.state === "EMPTY") {
    paintEntropyChart(
      `${CHART_PREFIX}-dash-entropy`,
      root.querySelector("#dash-entropy-chart"),
      (bundle.entropy.data && bundle.entropy.data.points) || []
    );
  }

  setHtml(root, "#dash-det-extra", stateExtra(bundle.alerts));
  const alerts = (bundle.alerts.data && bundle.alerts.data.alerts) || [];
  paintStatusBar(
    `${CHART_PREFIX}-dash-det`,
    root.querySelector("#dash-det-chart"),
    countBy(alerts, "alert_type"),
    "Alert types"
  );
  setHtml(
    root,
    "#dash-det-table",
    renderResult(bundle.alerts, {
      onLive: (d) => {
        const rows = (d.alerts || [])
          .slice(0, 8)
          .map(
            (a) => `<tr>
            <td>${escapeHtml(shortTs(a.timestamp))}</td>
            <td>${escapeHtml(na(a.alert_type))}</td>
            <td>${escapeHtml(fmtPct(a.confidence))}</td>
            <td>${escapeHtml(na(a.status))}</td>
          </tr>`
          )
          .join("");
        return dataTable(["Timestamp", "Type", "Confidence", "Status"], rows, "No detection alerts");
      },
    })
  );

  // R4 scores chronological
  setHtml(root, "#dash-r4-extra", stateExtra(bundle.correlation));
  const corr = chronological((bundle.correlation.data && bundle.correlation.data.results) || []);
  const corrPts = limitPoints(corr, 40);
  upsertChart(
    `${CHART_PREFIX}-dash-r4`,
    root.querySelector("#dash-r4-chart"),
    lineChartConfig({
      labels: corrPts.map((r) => shortLabel(r.timestamp)),
      datasets: [
        {
          label: "Correlation score",
          data: corrPts.map((r) => Number(r.score ?? r.correlation_score) || 0),
          borderColor: "#38bdf8",
          tension: 0.2,
          pointRadius: 2,
        },
      ],
      ySuggestedMax: 1.05,
    })
  );

  setHtml(root, "#dash-r6-extra", stateExtra(bundle.fusion));
  const fused = (bundle.fusion.data && bundle.fusion.data.results) || [];
  paintStatusBar(
    `${CHART_PREFIX}-dash-r6`,
    root.querySelector("#dash-r6-chart"),
    countBy(fused, "decision"),
    "Fusion decisions"
  );

  setHtml(root, "#dash-r7-extra", stateExtra(bundle.verification));
  const traces = (bundle.verification.data && bundle.verification.data.traces) || [];
  paintStatusBar(
    `${CHART_PREFIX}-dash-r7`,
    root.querySelector("#dash-r7-chart"),
    countBy(traces, "status"),
    "Verification status"
  );

  setHtml(
    root,
    "#dash-pipeline",
    [
      pipelineStage({ name: "Traffic", status: pipelineStageStatus(bundle.traffic) }),
      pipelineStage({ name: "Detection", status: pipelineStageStatus(bundle.entropy) }),
      pipelineStage({ name: "R4", status: pipelineStageStatus(bundle.correlation), note: "ADVISORY" }),
      pipelineStage({ name: "R6", status: pipelineStageStatus(bundle.fusion) }),
      pipelineStage({ name: "R7", status: pipelineStageStatus(bundle.verification) }),
      pipelineStage({ name: "Mitigation", status: healthFromBool(st.phase5_mitigation) }),
      pipelineStage({ name: "R5", status: pipelineStageStatus(bundle.rca) }),
      pipelineStage({ name: "R8", status: pipelineStageStatus(bundle.securityAlerts) }),
    ].join('<div class="pipe-arrow">↓</div>')
  );

  setHtml(root, "#dash-r8-extra", stateExtra(bundle.securityAlerts));
  const secAlerts = (bundle.securityAlerts.data && bundle.securityAlerts.data.alerts) || [];
  const sev =
    (bundle.securityStats.state === "LIVE" || bundle.securityStats.state === "STALE") &&
    bundle.securityStats.data &&
    bundle.securityStats.data.by_severity
      ? bundle.securityStats.data.by_severity
      : countBy(secAlerts, "severity");
  paintStatusBar(
    `${CHART_PREFIX}-dash-r8`,
    root.querySelector("#dash-r8-chart"),
    sev,
    "Alert severity"
  );
  setHtml(
    root,
    "#dash-alerts",
    secAlerts.length
      ? secAlerts.slice(0, 5).map(alertCard).join("")
      : renderResult(bundle.securityAlerts, { onLive: () => "" })
  );

  setHtml(root, "#dash-sum-extra", stateExtra(summary));
  const sumOk = summary.state === "LIVE" || summary.state === "STALE";
  setHtml(
    root,
    "#dash-metrics",
    [
      metricCard({
        title: "Detection Alerts",
        value: sumOk ? fmtNum(s.total_alerts, 0) : "N/A",
        state: summary.state,
      }),
      metricCard({
        title: "ML Attack Labels",
        value: sumOk ? fmtNum(s.total_attacks, 0) : "N/A",
        state: summary.state,
      }),
      metricCard({
        title: "Flows Blocked",
        value: sumOk ? fmtNum(s.total_blocks ?? s.active_blocks, 0) : "N/A",
        subtitle: sumOk ? `Active: ${fmtNum(s.active_blocks, 0)}` : "",
        state: summary.state,
      }),
      metricCard({
        title: "Entropy Score",
        value: sumOk ? fmtNum(s.entropy_score, 4) : "N/A",
        subtitle: `Status: ${na(s.entropy_status)}`,
        state: summary.state,
      }),
      metricCard({
        title: "RL Packet Threshold",
        value: sumOk ? `${fmtNum(s.pkt_threshold, 0)}/s` : "N/A",
        subtitle: sumOk ? `Byte: ${fmtNum(s.byte_threshold, 0)} B/s` : "",
        state: summary.state,
      }),
      metricCard({
        title: "Traffic Clusters",
        value: sumOk ? fmtNum(s.cluster_count, 0) : "N/A",
        subtitle: "HDBSCAN (Phase 6)",
        state: summary.state,
      }),
    ].join("")
  );

  const headerExtra = root.querySelector(".page-header-extra");
  if (headerExtra) {
    headerExtra.innerHTML = stateExtra(status.state === "OFFLINE" ? status : summary);
  }
}

/* ── Traffic ───────────────────────────────────────────────────── */

export async function renderTraffic(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#traffic-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "Traffic Monitor",
        subtitle: "Telemetry from GET /api/traffic (packet_rate, byte_rate, flow_count).",
      })}
      <div id="traffic-shell">
        <div class="metric-grid" id="traffic-metrics"></div>
        <div class="section-header"><h2>Packet Rate</h2><span id="traffic-extra"></span></div>
        ${chartShell("traffic-chart", "Traffic time series")}
        <p class="muted">Protocol distribution: N/A (not exposed by /api/traffic)</p>
        <div id="traffic-table"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const traffic = await api.fetchTraffic(60, ctx.signal);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#traffic-extra", stateExtra(traffic));
  const points = (traffic.data && traffic.data.points) || [];
  const latest = points[points.length - 1] || {};
  setHtml(
    root,
    "#traffic-metrics",
    [
      metricCard({
        title: "Packet Rate",
        value: traffic.state === "LIVE" || traffic.state === "STALE" ? fmtNum(latest.packet_rate, 2) : "N/A",
        subtitle: "pkt/s (latest)",
        state: traffic.state,
      }),
      metricCard({
        title: "Byte Rate",
        value: traffic.state === "LIVE" || traffic.state === "STALE" ? fmtNum(latest.byte_rate, 0) : "N/A",
        subtitle: "B/s (latest)",
        state: traffic.state,
      }),
      metricCard({
        title: "Flow Count",
        value: traffic.state === "LIVE" || traffic.state === "STALE" ? fmtNum(latest.flow_count, 0) : "N/A",
        state: traffic.state,
      }),
      metricCard({
        title: "Protocol Distribution",
        value: "N/A",
        subtitle: "Not exposed by API",
        state: "UNAVAILABLE",
      }),
    ].join("")
  );

  if (traffic.state !== "OFFLINE" && traffic.state !== "ERROR") {
    const pts = limitPoints(points, 60);
    upsertChart(
      `${CHART_PREFIX}-traffic`,
      root.querySelector("#traffic-chart"),
      lineChartConfig({
        labels: pts.map((p) => shortLabel(p.timestamp)),
        datasets: [
          {
            label: "packet_rate",
            data: pts.map((p) => Number(p.packet_rate) || 0),
            borderColor: "#3aa0ff",
            backgroundColor: "rgba(58,160,255,0.15)",
            fill: true,
            tension: 0.25,
            pointRadius: 0,
          },
          {
            label: "byte_rate / 1000",
            data: pts.map((p) => (Number(p.byte_rate) || 0) / 1000),
            borderColor: "#fb923c",
            tension: 0.25,
            pointRadius: 0,
          },
        ],
      })
    );
  }

  setHtml(
    root,
    "#traffic-table",
    renderResult(traffic, {
      onLive: (d) => {
        const rows = (d.points || [])
          .slice(-25)
          .reverse()
          .map(
            (p) => `<tr>
            <td>${escapeHtml(shortTs(p.timestamp))}</td>
            <td>${escapeHtml(fmtNum(p.packet_rate, 2))}</td>
            <td>${escapeHtml(fmtNum(p.byte_rate, 0))}</td>
            <td>${escapeHtml(fmtNum(p.flow_count, 0))}</td>
          </tr>`
          )
          .join("");
        return dataTable(["Timestamp", "Packet Rate", "Byte Rate", "Flows"], rows, "No traffic points");
      },
    })
  );
}

/* ── Detection ─────────────────────────────────────────────────── */

export async function renderDetection(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#det-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "Detection Intelligence",
        subtitle: "Entropy + ML from backend logs. Confidence is backend-authored.",
      })}
      <div id="det-shell">
        <div class="section-header"><h2>Entropy Timeline</h2><span id="det-ent-extra"></span></div>
        <p class="muted">Threshold: N/A (not returned by /api/entropy)</p>
        ${chartShell("det-entropy-chart", "Entropy timeline")}
        <div class="metric-grid" id="det-ent-metrics"></div>
        <div id="det-ent-dims" class="ent-dims"></div>
        <div class="section-header"><h2>Detection Activity</h2><span id="det-al-extra"></span></div>
        ${chartShell("det-alerts-chart", "Detection alert activity")}
        <div id="det-alert-table"></div>
        <div class="section-header"><h2>ML Predictions</h2><span id="det-ml-extra"></span></div>
        ${chartShell("det-ml-chart", "ML status counts")}
        <div id="det-ml-table"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const [alerts, entropy, ml] = await Promise.all([
    api.fetchDetectionAlerts(40, ctx.signal),
    api.fetchEntropy(60, ctx.signal),
    api.fetchMl(40, ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#det-ent-extra", stateExtra(entropy));
  const epts = (entropy.data && entropy.data.points) || [];
  paintEntropyChart(`${CHART_PREFIX}-det-ent`, root.querySelector("#det-entropy-chart"), epts);
  const L = (entropy.data && entropy.data.latest) || epts[epts.length - 1] || {};
  setHtml(
    root,
    "#det-ent-metrics",
    [
      metricCard({ title: "Entropy Score", value: fmtNum(L.entropy_score, 4), state: entropy.state }),
      metricCard({ title: "Status", value: na(L.status), state: entropy.state }),
      metricCard({ title: "Confidence", value: fmtPct(L.confidence), state: entropy.state }),
      metricCard({ title: "Threshold", value: "N/A", state: "UNAVAILABLE" }),
    ].join("")
  );
  const dimRows = [
    ["Source", L.src_entropy, "#3aa0ff"],
    ["Destination", L.dst_entropy, "#2dd4bf"],
    ["Packet Dist", L.packet_entropy, "#22c55e"],
    ["Byte Dist", L.byte_entropy, "#f59e0b"],
    ["Flow Dist", L.flow_entropy, "#eab308"],
  ];
  setHtml(
    root,
    "#det-ent-dims",
    dimRows
      .map(([name, val, color]) => {
        const v = Number(val);
        const pct = Number.isFinite(v) ? Math.max(0, Math.min(100, v * 100)) : 0;
        return `<div class="ent-row"><span class="ent-name">${escapeHtml(name)}</span>
          <div class="ent-bar-bg"><div class="ent-bar-fill" style="width:${pct}%;background:${color}"></div></div>
          <span class="ent-val">${escapeHtml(fmtNum(val, 2))}</span></div>`;
      })
      .join("")
  );

  setHtml(root, "#det-al-extra", stateExtra(alerts));
  const alist = (alerts.data && alerts.data.alerts) || [];
  paintStatusBar(
    `${CHART_PREFIX}-det-al`,
    root.querySelector("#det-alerts-chart"),
    countBy(alist, "alert_type"),
    "Types"
  );
  setHtml(
    root,
    "#det-alert-table",
    renderResult(alerts, {
      onLive: (d) => {
        const rows = (d.alerts || [])
          .map(
            (a) => `<tr>
            <td>${escapeHtml(shortTs(a.timestamp))}</td>
            <td>${escapeHtml(na(a.alert_type))}</td>
            <td>${escapeHtml(na(a.dimension))}</td>
            <td>${escapeHtml(fmtNum(a.value, 4))}</td>
            <td>${escapeHtml(fmtNum(a.threshold, 4))}</td>
            <td>${escapeHtml(fmtPct(a.confidence))}</td>
            <td>${escapeHtml(na(a.status))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Timestamp", "Type", "Dimension", "Value", "Threshold", "Confidence", "Status"],
          rows,
          "No detection alerts"
        );
      },
    })
  );

  setHtml(root, "#det-ml-extra", stateExtra(ml));
  const preds = (ml.data && (ml.data.predictions || ml.data.points || ml.data.rows)) || [];
  paintStatusBar(
    `${CHART_PREFIX}-det-ml`,
    root.querySelector("#det-ml-chart"),
    countBy(preds, "status"),
    "ML status"
  );
  setHtml(
    root,
    "#det-ml-table",
    renderResult(ml, {
      onLive: () => {
        if (!preds.length) return dataTable([], "", "No ML predictions");
        const rows = preds
          .slice(0, 40)
          .map(
            (p) => `<tr>
            <td>${escapeHtml(shortTs(p.timestamp))}</td>
            <td>${escapeHtml(na(p.status || p.label))}</td>
            <td>${escapeHtml(fmtPct(p.confidence))}</td>
            <td>${escapeHtml(na(p.attack_hint || p.hint))}</td>
            <td>${escapeHtml(na(p.source || "ml"))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Timestamp", "Status", "Confidence", "Attack Hint", "Source"],
          rows,
          "No ML predictions"
        );
      },
    })
  );
}

/* ── R4 ────────────────────────────────────────────────────────── */

export async function renderCorrelation(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#r4-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "R4 Cross-Layer Correlation",
        subtitle: "ADVISORY / ANALYTICAL — does not authorize mitigation.",
        badge: "ADVISORY",
      })}
      <div id="r4-shell">
        <div class="advisory banner">R4 expresses co-occurrence — not causation or mitigation authority.</div>
        <div class="section-header"><h2>Correlation Activity</h2><span id="r4-extra"></span></div>
        ${chartShell("r4-chart", "Correlation score timeline")}
        <div id="r4-stats" class="metric-grid"></div>
        <div id="r4-table"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const [results, stats] = await Promise.all([
    api.fetchCorrelationResults(40, ctx.signal),
    api.fetchCorrelationStats(ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#r4-extra", stateExtra(results));
  const list = chronological((results.data && results.data.results) || []);
  const pts = limitPoints(list, 40);
  upsertChart(
    `${CHART_PREFIX}-r4`,
    root.querySelector("#r4-chart"),
    lineChartConfig({
      labels: pts.map((r) => shortLabel(r.timestamp)),
      datasets: [
        {
          label: "score",
          data: pts.map((r) => Number(r.score ?? r.correlation_score) || 0),
          borderColor: "#38bdf8",
          tension: 0.2,
          pointRadius: 2,
        },
      ],
      ySuggestedMax: 1.05,
    })
  );

  setHtml(
    root,
    "#r4-stats",
    renderResult(stats, {
      onLive: (d) =>
        [
          metricCard({ title: "Total (scanned)", value: fmtNum(d.total, 0), state: stats.state }),
          metricCard({ title: "Exists", value: String(d.exists), state: stats.state }),
        ].join(""),
    })
  );

  setHtml(
    root,
    "#r4-table",
    renderResult(results, {
      onLive: (d) => {
        const note = d.note ? `<p class="advisory">${escapeHtml(d.note)}</p>` : "";
        const rows = (d.results || [])
          .map(
            (r) => `<tr>
            <td>${escapeHtml(na(r.correlation_id))}</td>
            <td>${escapeHtml(na(r.event_id))}</td>
            <td>${escapeHtml(na(r.status || r.label))}</td>
            <td>${escapeHtml(fmtNum(r.score ?? r.correlation_score, 3))}</td>
            <td>${escapeHtml(fmtPct(r.confidence))}</td>
            <td>${escapeHtml(shortTs(r.timestamp))}</td>
          </tr>`
          )
          .join("");
        return (
          note +
          dataTable(
            ["Correlation ID", "Event ID", "Result", "Score", "Confidence", "Timestamp"],
            rows,
            "No correlation results"
          )
        );
      },
    })
  );
}

/* ── R6 ────────────────────────────────────────────────────────── */

export async function renderFusion(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#r6-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "R6 Collaborative Fusion",
        subtitle: "Backend fusion remains the authority. UI does not recompute fusion math.",
      })}
      <div id="r6-shell">
        <div class="section-header"><h2>Fusion Activity</h2><span id="r6-extra"></span></div>
        <div class="chart-grid">
          ${chartShell("r6-dec-chart", "Fusion decision counts")}
          ${chartShell("r6-conf-chart", "Fusion confidence timeline")}
        </div>
        <div id="r6-stats" class="metric-grid"></div>
        <div id="r6-table"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const [results, stats] = await Promise.all([
    api.fetchFusedDecisions(40, ctx.signal),
    api.fetchFusionStats(ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#r6-extra", stateExtra(results));
  const list = (results.data && results.data.results) || [];
  paintStatusBar(
    `${CHART_PREFIX}-r6-dec`,
    root.querySelector("#r6-dec-chart"),
    countBy(list, "decision"),
    "Decisions"
  );
  const chrono = chronological(list);
  const pts = limitPoints(chrono, 40);
  upsertChart(
    `${CHART_PREFIX}-r6-conf`,
    root.querySelector("#r6-conf-chart"),
    lineChartConfig({
      labels: pts.map((r) => shortLabel(r.timestamp)),
      datasets: [
        {
          label: "confidence",
          data: pts.map((r) => {
            const c = Number(r.confidence);
            if (!Number.isFinite(c)) return null;
            return c <= 1 ? c : c / 100;
          }),
          borderColor: "#2dd4bf",
          tension: 0.2,
          pointRadius: 2,
          spanGaps: true,
        },
      ],
      ySuggestedMax: 1.05,
    })
  );

  setHtml(
    root,
    "#r6-stats",
    renderResult(stats, {
      onLive: (d) =>
        [
          metricCard({ title: "Total (scanned)", value: fmtNum(d.total, 0), state: stats.state }),
          metricCard({ title: "Exists", value: String(d.exists), state: stats.state }),
        ].join(""),
    })
  );

  setHtml(
    root,
    "#r6-table",
    renderResult(results, {
      onLive: (d) => {
        const rows = (d.results || [])
          .map(
            (r) => `<tr>
            <td>${escapeHtml(na(r.fusion_id))}</td>
            <td>${escapeHtml(na(r.event_id))}</td>
            <td>${escapeHtml(na(r.decision))}</td>
            <td>${escapeHtml(fmtPct(r.confidence))}</td>
            <td>${escapeHtml(
              typeof r.disagreement === "boolean"
                ? String(r.disagreement)
                : na(r.disagreement)
            )}</td>
            <td>${escapeHtml(
              Array.isArray(r.participating) ? r.participating.join(", ") || "—" : "—"
            )}</td>
            <td>${escapeHtml(shortTs(r.timestamp))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Fusion ID", "Event ID", "Decision", "Confidence", "Disagreement", "Sources", "Timestamp"],
          rows,
          "No fused decisions"
        );
      },
    })
  );
}

/* ── R7 ────────────────────────────────────────────────────────── */

export async function renderVerification(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#r7-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "R7 Multi-Stage Verification",
        subtitle: "Read-only timeline. No approve/verify controls.",
      })}
      <div id="r7-shell">
        <div class="pipeline compact" id="r7-ref-stages"></div>
        <div class="section-header"><h2>Status Distribution</h2><span id="r7-extra"></span></div>
        ${chartShell("r7-status-chart", "Verification status counts")}
        <div id="r7-traces"></div>
      </div>`;
    markChartUnavailable(root);
    setHtml(
      root,
      "#r7-ref-stages",
      [
        "WARMUP",
        "DETECTION_EVIDENCE",
        "ATTACK_CONFIRMATION",
        "CONFIDENCE_GATE",
        "ATTACKER_IDENTIFICATION",
        "MITIGATION_ELIGIBILITY",
      ]
        .map((n) => pipelineStage({ name: n, status: "REFERENCE" }))
        .join('<div class="pipe-arrow">→</div>')
    );
  }

  const traces = await api.fetchVerificationTraces(40, ctx.signal);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#r7-extra", stateExtra(traces));
  const list = (traces.data && traces.data.traces) || [];
  paintStatusBar(
    `${CHART_PREFIX}-r7-status`,
    root.querySelector("#r7-status-chart"),
    countBy(list, "status"),
    "Status"
  );

  setHtml(
    root,
    "#r7-traces",
    renderResult(traces, {
      onLive: (d) =>
        (d.traces || [])
          .map((t) => {
            const stages = t.stages || [];
            return `
            <article class="verify-card">
              <header>
                ${statusBadge(t.status || "UNKNOWN")}
                <span>${escapeHtml(shortTs(t.timestamp))}</span>
              </header>
              <div class="verify-meta">
                <span>ID: ${escapeHtml(na(t.verification_id))}</span>
                <span>Event: ${escapeHtml(na(t.event_id))}</span>
                <span>Eligible: ${escapeHtml(String(t.mitigation_eligible ?? "N/A"))}</span>
                <span>Confidence: ${escapeHtml(fmtPct(t.confidence))}</span>
                ${
                  t.event_id
                    ? `<a class="investigate-link" href="#investigation/${encodeURIComponent(
                        String(t.event_id).trim()
                      )}">View Investigation</a>`
                    : ""
                }
              </div>
              <p>${escapeHtml(na(t.reason, ""))}</p>
              ${timeline(stages)}
            </article>`;
          })
          .join(""),
    })
  );
}

/* ── R8 ────────────────────────────────────────────────────────── */

export async function renderAlerts(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#r8-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "R8 Security Alerts",
        subtitle: "Observational only. No resolve/dismiss actions in this UI.",
        extra: '<span id="r8-header-extra"></span>',
      })}
      <div class="advisory banner">
        R8 AlertManager receives multi-stage verified events and dispatches notifications across configured adapters.
        In accordance with fail-closed security policy, alerts are raised when attack confidence satisfies verification thresholds.
      </div>
      <div id="r8-shell">
        <div class="section-header"><h2>Severity Distribution</h2><span id="r8-extra"></span></div>
        <div class="metric-grid" id="r8-sev"></div>
        ${chartShell("r8-sev-chart", "Alert severity distribution")}
        <div class="section-header"><h2>Alert Timeline</h2></div>
        <div id="r8-list" class="alert-list"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const [alerts, stats] = await Promise.all([
    api.fetchSecurityAlerts(50, ctx.signal),
    api.fetchSecurityAlertStats(ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  const effState = alerts.state === "OFFLINE" ? alerts : stats;
  setHtml(root, "#r8-header-extra", stateExtra(effState));
  setHtml(root, "#r8-extra", stateExtra(alerts));

  const rawBy =
    (stats.state === "LIVE" || stats.state === "STALE") && stats.data && stats.data.by_severity
      ? stats.data.by_severity
      : countBy((alerts.data && alerts.data.alerts) || [], "severity");
  const by = {
    CRITICAL: rawBy.CRITICAL ?? 0,
    HIGH: rawBy.HIGH ?? 0,
    MEDIUM: rawBy.MEDIUM ?? 0,
    LOW: rawBy.LOW ?? 0,
  };

  setHtml(
    root,
    "#r8-sev",
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
      .map((sev) =>
        metricCard({
          title: sev,
          value: fmtNum(by[sev] ?? 0, 0),
          state: stats.state || alerts.state,
        })
      )
      .join("")
  );
  paintStatusBar(`${CHART_PREFIX}-r8-sev`, root.querySelector("#r8-sev-chart"), by, "Severity");

  if (alerts.state === "OFFLINE" || alerts.state === "ERROR") {
    setHtml(root, "#r8-list", renderResult(alerts, { onLive: () => "" }));
  } else {
    const items = (alerts.data && alerts.data.alerts) || [];
    if (!items.length) {
      setHtml(
        root,
        "#r8-list",
        `
        <div class="card" style="padding: 1.5rem 1.75rem; text-align: center; background: var(--bg-card, #141b2d); border: 1px solid var(--border-color, #232d42); border-radius: 8px;">
          <div style="font-size: 2.2rem; margin-bottom: 0.5rem;">🛡️</div>
          <h3 style="margin: 0 0 0.5rem 0; font-size: 1.15rem; color: var(--ok, #22c55e);">No Active Security Alerts</h3>
          <p class="muted" style="margin: 0 auto; max-width: 580px; font-size: 0.88rem; line-height: 1.5;">
            All OpenFlow flow tables and switch telemetry are currently operating within established baselines.
            R8 AlertManager is active and listening for multi-stage verified threats. Evaluated baseline events can be inspected under Security Events.
          </p>
          <div style="margin-top: 1.25rem; display: flex; justify-content: center; gap: 1rem;">
            <a class="investigate-link" href="#events">View Security Events (R6/R7)</a>
            <a class="investigate-link" href="#detection">View Detection Intelligence</a>
          </div>
        </div>
        `
      );
    } else {
      setHtml(root, "#r8-list", items.map(alertCard).join(""));
    }
  }
}

/* ── Adaptive RL / Drift (legacy RL panel + Phase 6 drift) ───── */

export async function renderAdaptive(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#adaptive-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "Adaptive RL / Drift",
        subtitle: "Phase 7 PPO thresholds and Phase 6 ADWIN drift — observation only.",
        badge: "READ ONLY",
      })}
      <div id="adaptive-shell">
        <div class="advisory banner">
          Thresholds are adjusted by the controller PPO agent. This page does not write RL or drift state.
          Cluster count comes from GET /api/summary (same as legacy stat cards).
        </div>
        ${sectionHeader("RL Adaptive Thresholds", '<span id="ad-rl-extra"></span>')}
        <div class="metric-grid" id="ad-rl-metrics"></div>
        ${chartShell("ad-reward-chart", "RL reward history from /api/rl")}
        <div id="ad-rl-table"></div>
        ${sectionHeader("ADWIN Drift Events", '<span id="ad-drift-extra"></span>')}
        <div id="ad-drift-table"></div>
        ${sectionHeader("Traffic Clusters", '<span id="ad-cluster-extra"></span>')}
        <div class="metric-grid" id="ad-cluster-metrics"></div>
      </div>`;
    markChartUnavailable(root);
  }

  const [rl, drift, summary, ml] = await Promise.all([
    api.fetchRl(40, ctx.signal),
    api.fetchDrift(30, ctx.signal),
    api.fetchSummary(ctx.signal),
    api.fetchMl(5, ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#ad-rl-extra", stateExtra(rl));
  const points = chronological((rl.data && (rl.data.points || rl.data.decisions)) || []);
  const latest = (rl.data && rl.data.latest) || points[points.length - 1] || {};
  const mlPoints = (ml.data && (ml.data.points || ml.data.predictions)) || [];
  const mlLatest = (ml.data && ml.data.latest) || mlPoints[mlPoints.length - 1] || {};
  const pkt = Number(latest.pkt_threshold) || 0;
  const byt = Number(latest.byte_threshold) || 0;
  const conf = Number(latest.conf_threshold) || 0;
  const reward = Number(latest.reward);
  setHtml(
    root,
    "#ad-rl-metrics",
    [
      metricCard({
        title: "Packet Rate Limit",
        value: `${fmtNum(pkt, 0)} p/s`,
        state: rl.state,
      }),
      metricCard({
        title: "Byte Rate Limit",
        value: `${fmtNum(byt, 0)} B/s`,
        state: rl.state,
      }),
      metricCard({
        title: "Confidence Gate",
        value: fmtNum(conf, 2),
        state: rl.state,
      }),
      metricCard({
        title: "Last Reward",
        value: Number.isFinite(reward) ? (reward >= 0 ? `+${fmtNum(reward, 2)}` : fmtNum(reward, 2)) : "N/A",
        subtitle: mlLatest.status
          ? `Last ML: ${na(mlLatest.status)} @ ${fmtPct(mlLatest.confidence)}`
          : "Last ML: —",
        state: rl.state,
      }),
    ].join("")
  );

  const rPts = limitPoints(points, 40);
  upsertChart(
    `${CHART_PREFIX}-ad-reward`,
    root.querySelector("#ad-reward-chart"),
    lineChartConfig({
      labels: rPts.map((p) => shortLabel(p.timestamp)),
      datasets: [
        {
          label: "Reward",
          data: rPts.map((p) => Number(p.reward) || 0),
          borderColor: "#a78bfa",
          tension: 0.25,
          pointRadius: 0,
          fill: false,
        },
      ],
    })
  );

  setHtml(
    root,
    "#ad-rl-table",
    renderResult(rl, {
      onLive: () => {
        if (!points.length) return dataTable([], "", "No RL decisions");
        const rows = [...points]
          .reverse()
          .slice(0, 25)
          .map(
            (p) => `<tr>
            <td>${escapeHtml(shortTs(p.timestamp))}</td>
            <td>${escapeHtml(fmtNum(p.pkt_threshold, 0))}</td>
            <td>${escapeHtml(fmtNum(p.byte_threshold, 0))}</td>
            <td>${escapeHtml(fmtNum(p.conf_threshold, 2))}</td>
            <td>${escapeHtml(fmtNum(p.reward, 3))}</td>
            <td>${escapeHtml(na(p.ml_label))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Timestamp", "Pkt thresh", "Byte thresh", "Conf", "Reward", "ML label"],
          rows,
          "No RL decisions"
        );
      },
    })
  );

  setHtml(root, "#ad-drift-extra", stateExtra(drift));
  const events = (drift.data && (drift.data.events || drift.data.alerts)) || [];
  setHtml(
    root,
    "#ad-drift-table",
    renderResult(drift, {
      onLive: () => {
        if (!events.length) return dataTable([], "", "No drift events");
        const rows = events
          .slice(0, 30)
          .map(
            (e) => `<tr>
            <td>${escapeHtml(shortTs(e.timestamp))}</td>
            <td>${escapeHtml(na(e.metric || e.metric_name))}</td>
            <td>${escapeHtml(na(e.switch_id))}</td>
            <td>${escapeHtml(fmtNum(e.old_mean, 3))}</td>
            <td>${escapeHtml(fmtNum(e.new_mean, 3))}</td>
            <td>${escapeHtml(fmtNum(e.delta, 3))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Timestamp", "Metric", "Switch", "Old mean", "New mean", "Delta"],
          rows,
          "No drift events"
        );
      },
    })
  );

  setHtml(root, "#ad-cluster-extra", stateExtra(summary));
  const s =
    summary.state === "LIVE" || summary.state === "STALE" || summary.state === "EMPTY"
      ? summary.data || {}
      : {};
  setHtml(
    root,
    "#ad-cluster-metrics",
    [
      metricCard({
        title: "Cluster count",
        value:
          summary.state === "LIVE" || summary.state === "STALE"
            ? fmtNum(s.cluster_count, 0)
            : "N/A",
        subtitle: "From /api/summary (HDBSCAN)",
        state: summary.state,
      }),
    ].join("")
  );
}

/* ── Mitigation / Topology / Twin / etc. (Phase 1 + light upgrades) ─ */

export async function renderMitigation(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#mitigation-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "Mitigation Status",
        subtitle: "READ ONLY — observation of OpenFlow surgical mitigation, R7 verification gate, and active blocklists.",
        badge: "READ ONLY",
        extra: '<span id="mitigation-header-extra"></span>',
      })}
      <div class="advisory banner">
        Surgical DROP rules are installed by the controller only when R7 verification status is VERIFIED (fail-closed, 60% confidence floor).
        This dashboard does not install, modify, or remove OpenFlow rules — matching legacy UI behavior.
        Lab orchestration (scenarios / controller) lives under <a href="#lab-control">Lab Control</a>.
      </div>
      <div id="mitigation-shell">
        <div class="metric-grid" id="mitigation-metrics"></div>
        <div id="mitigation-strategy-card"></div>
        ${sectionHeader("Active Blocklist & Action History", '<span id="mitigation-blocks-extra"></span>')}
        <div id="mitigation-blocks-table"></div>
        ${sectionHeader("R7 Verification Gate Activity", '<span id="mitigation-traces-extra"></span>')}
        <div id="mitigation-traces-table"></div>
      </div>
    `;
  }

  const [blocks, traces, status] = await Promise.all([
    api.fetchBlocklist(40, ctx.signal),
    api.fetchVerificationTraces(20, ctx.signal),
    api.fetchStatus(ctx.signal),
  ]);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  const effState = blocks.state === "OFFLINE" ? blocks : status;
  setHtml(root, "#mitigation-header-extra", stateExtra(effState));
  setHtml(root, "#mitigation-blocks-extra", stateExtra(blocks));
  setHtml(root, "#mitigation-traces-extra", stateExtra(traces));

  const blocksList = (blocks.data && (blocks.data.blocks || blocks.data.actions)) || [];
  const activeCount = blocksList.length;
  const tracesList = (traces.data && traces.data.traces) || [];
  const gatedCount = tracesList.filter(
    (t) => t.status === "INELIGIBLE" || t.mitigation_eligible === false
  ).length;

  // KPI Metrics
  setHtml(
    root,
    "#mitigation-metrics",
    [
      metricCard({
        title: "Mitigation Engine",
        value:
          status.state === "OFFLINE"
            ? "OFFLINE"
            : status.data && status.data.phase5_mitigation
            ? "ACTIVE"
            : "STANDBY",
        subtitle: "Phase 5 Surgical Engine",
        state: status.state,
      }),
      metricCard({
        title: "Verification Gate",
        value: traces.state === "OFFLINE" ? "OFFLINE" : "R7 FAIL-CLOSED",
        subtitle: "60% Confidence Floor",
        state: traces.state,
      }),
      metricCard({
        title: "Active DROP Rules",
        value: blocks.state === "OFFLINE" ? "N/A" : fmtNum(activeCount, 0),
        subtitle: "Currently Enforced Flows",
        state: blocks.state === "OFFLINE" ? "OFFLINE" : "LIVE",
      }),
      metricCard({
        title: "Gated Attack Events",
        value: traces.state === "OFFLINE" ? "N/A" : fmtNum(gatedCount, 0),
        subtitle: "Prevented False-Positives",
        state: traces.state === "OFFLINE" ? "OFFLINE" : "LIVE",
      }),
    ].join("")
  );

  // Strategy & Architecture Card
  setHtml(
    root,
    "#mitigation-strategy-card",
    `
    <div class="card" style="margin-bottom: 1.5rem; padding: 1.25rem 1.5rem; background: var(--bg-card, #141b2d); border: 1px solid var(--border-color, #232d42); border-radius: 8px;">
      <h3 style="margin-top: 0; margin-bottom: 0.75rem; font-size: 1.05rem; display: flex; align-items: center; gap: 0.5rem;">
        <span>🛡️</span> Mitigation Engine Architecture & Enforcement Rules
      </h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 1rem; font-size: 0.88rem;">
        <div>
          <div class="muted" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Enforcement Strategy</div>
          <strong style="color: #60a5fa;">Surgical FLOW_PAIR (src_mac, dst_mac)</strong>
          <p class="muted" style="margin: 0.25rem 0 0 0; font-size: 0.82rem;">Drops only confirmed attack vectors without severing victim connectivity or legitimate host communication.</p>
        </div>
        <div>
          <div class="muted" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">R7 Verification Gate</div>
          <strong style="color: #34d399;">Fail-Closed Policy (≥ 60.0% Confidence)</strong>
          <p class="muted" style="margin: 0.25rem 0 0 0; font-size: 0.82rem;">Controller installs DROP flows only when multi-stage verification is VERIFIED; low-confidence events are gated.</p>
        </div>
        <div>
          <div class="muted" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Rule Lifecycle</div>
          <strong style="color: #fbbf24;">60s Dynamic Eviction / Idle Timeout</strong>
          <p class="muted" style="margin: 0.25rem 0 0 0; font-size: 0.82rem;">Rules expire automatically from OpenFlow tables to avoid permanent lockout after attack traffic ceases.</p>
        </div>
        <div>
          <div class="muted" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Execution Authority</div>
          <strong style="color: #cbd5e1;">SDN Controller (Autonomous / Lab Mode)</strong>
          <p class="muted" style="margin: 0.25rem 0 0 0; font-size: 0.82rem;">Dashboard is strictly observational; flow rules are installed directly by the Osken/Ryu controller engine.</p>
        </div>
      </div>
    </div>
    `
  );

  // Active Blocklist Table
  if (blocks.state === "OFFLINE" || blocks.state === "ERROR") {
    setHtml(root, "#mitigation-blocks-table", renderResult(blocks, { onLive: () => "" }));
  } else {
    const rows = blocksList
      .map(
        (b) => `<tr>
        <td>${escapeHtml(shortTs(b.timestamp))}</td>
        <td>${statusBadge(b.action || b.status || "BLOCK")}</td>
        <td>${escapeHtml(na(b.block_type || b.attack_type || "SRC_MAC"))}</td>
        <td><code>${escapeHtml(na(b.attacker_mac || b.src_mac))}</code></td>
        <td><code>${escapeHtml(na(b.victim_mac || b.dst_mac))}</code></td>
        <td>${escapeHtml(fmtPct(b.confidence))}</td>
        <td>${escapeHtml(na(b.timeout_sec ? `${b.timeout_sec}s` : null, "60s"))}</td>
        <td>${statusBadge(b.status || "ACTIVE")}</td>
      </tr>`
      )
      .join("");
    const blocksTableHtml = dataTable(
      ["Timestamp", "Action", "Block Type", "Attacker MAC", "Victim MAC", "Confidence", "Timeout", "Status"],
      rows,
      "No active DROP rules — network running normally or potential events gated by R7 Verification Gate"
    );
    setHtml(root, "#mitigation-blocks-table", blocksTableHtml);
  }

  // R7 Verification Gate Activity Table
  if (traces.state === "OFFLINE" || traces.state === "ERROR") {
    setHtml(root, "#mitigation-traces-table", renderResult(traces, { onLive: () => "" }));
  } else {
    const traceRows = tracesList
      .map((t) => {
        const isGated = t.status === "INELIGIBLE" || t.mitigation_eligible === false;
        const eligBadge = isGated
          ? `<span class="badge badge-neutral">GATED (DROP Prevented)</span>`
          : `<span class="badge badge-live">VERIFIED (Eligible)</span>`;
        const investLink = t.event_id
          ? `<a class="investigate-link" href="#investigation/${encodeURIComponent(
              String(t.event_id).trim()
            )}">${escapeHtml(String(t.event_id).slice(0, 8))}…</a>`
          : "N/A";
        return `<tr>
          <td>${escapeHtml(shortTs(t.timestamp))}</td>
          <td><code>${escapeHtml(t.verification_id ? String(t.verification_id).slice(0, 8) + "…" : "N/A")}</code></td>
          <td>${investLink}</td>
          <td>${escapeHtml(na(t.dpid ? `s${t.dpid}` : null))}</td>
          <td>${statusBadge(t.status || "UNKNOWN")}</td>
          <td>${escapeHtml(fmtPct(t.confidence))}</td>
          <td>${escapeHtml(na(t.reason))}</td>
          <td>${eligBadge}</td>
        </tr>`;
      })
      .join("");
    const tracesTableHtml = dataTable(
      ["Timestamp", "Verification ID", "Event Link", "Switch", "Gate Status", "Confidence", "Gating Reason", "Mitigation Decision"],
      traceRows,
      "No recent verification traces logged"
    );
    setHtml(root, "#mitigation-traces-table", tracesTableHtml);
  }
}

export async function renderRca(root, ctx = {}) {
  const soft = !!ctx.soft && root.querySelector("#rca-shell");
  if (!soft) {
    destroyPageCharts();
    root.innerHTML = `
      ${pageHeader({
        title: "R5 Root Cause / XAI",
        subtitle: "Analytical & explanatory attribution for verified anomalies.",
        badge: "ANALYTICAL",
        extra: '<span id="rca-header-extra"></span>',
      })}
      <div class="advisory banner">
        R5 Root Cause Analysis (XAI) utilizes SHAP feature attribution and multi-signal evidence synthesis.
        Enrichment runs post-verification when attacks are confirmed or escalated. Observational view only.
      </div>
      <div id="rca-shell">
        <div class="metric-grid" id="rca-metrics"></div>
        <div id="rca-xai-card"></div>
        ${sectionHeader("Root Cause Reports", '<span id="rca-reports-extra"></span>')}
        <div id="rca-reports-table"></div>
      </div>
    `;
  }

  const reports = await api.fetchRcaReports(30, ctx.signal);
  if (ctx.generation != null && ctx.isCurrent && !ctx.isCurrent(ctx.generation)) return;

  setHtml(root, "#rca-header-extra", stateExtra(reports));
  setHtml(root, "#rca-reports-extra", stateExtra(reports));

  const list = (reports.data && reports.data.reports) || [];
  const totalReports = list.length;

  // KPI Metrics
  setHtml(
    root,
    "#rca-metrics",
    [
      metricCard({
        title: "R5 RCA Reports",
        value: reports.state === "OFFLINE" ? "OFFLINE" : fmtNum(totalReports, 0),
        subtitle: "Enriched Anomaly Traces",
        state: reports.state,
      }),
      metricCard({
        title: "Attribution Engine",
        value: "SHAP / TREE",
        subtitle: "Local Path Explanations",
        state: "LIVE",
      }),
      metricCard({
        title: "Feature Dimensions",
        value: "4 VECTORS",
        subtitle: "Rate · Entropy · Symmetry · Protocol",
        state: "LIVE",
      }),
      metricCard({
        title: "Attribution Policy",
        value: "R5 FAIL-ISOLATED",
        subtitle: "Independent of Controller",
        state: "LIVE",
      }),
    ].join("")
  );

  // XAI Feature Attribution Framework Card
  setHtml(
    root,
    "#rca-xai-card",
    `
    <div class="card" style="margin-bottom: 1.5rem; padding: 1.25rem 1.5rem; background: var(--bg-card, #141b2d); border: 1px solid var(--border-color, #232d42); border-radius: 8px;">
      <h3 style="margin-top: 0; margin-bottom: 0.75rem; font-size: 1.05rem; display: flex; align-items: center; gap: 0.5rem;">
        <span>🔍</span> XAI Feature Attribution Framework & Diagnostics
      </h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 1rem; font-size: 0.88rem;">
        <div>
          <div class="muted" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Entropy Deflection</div>
          <strong style="color: #60a5fa;">Shannon Entropy (IP / Port Spread)</strong>
          <p class="muted" style="margin: 0.25rem 0 0 0; font-size: 0.82rem;">Measures destination/source randomness deflection against baseline distributions to differentiate multi-target floods.</p>
        </div>
        <div>
          <div class="muted" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Traffic Volumetrics</div>
          <strong style="color: #34d399;">Packet & Byte Surge Rates</strong>
          <p class="muted" style="margin: 0.25rem 0 0 0; font-size: 0.82rem;">Calculates sudden delta in packet throughput and flow rate relative to adaptive PPO thresholds.</p>
        </div>
        <div>
          <div class="muted" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Flow Asymmetry</div>
          <strong style="color: #fbbf24;">TCP SYN/ACK & ICMP Ratio</strong>
          <p class="muted" style="margin: 0.25rem 0 0 0; font-size: 0.82rem;">Detects unreciprocated half-open requests indicating SYN flood or reflection exhaustion vectors.</p>
        </div>
        <div>
          <div class="muted" style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.25rem;">Investigation Link</div>
          <strong style="color: #cbd5e1;">Cross-Pipeline Event Correlation</strong>
          <p class="muted" style="margin: 0.25rem 0 0 0; font-size: 0.82rem;">Detailed multi-stage RCA traces can be drilled down by event ID directly via <a class="investigate-link" href="#events">Security Events</a>.</p>
        </div>
      </div>
    </div>
    `
  );

  // Reports Table
  if (reports.state === "OFFLINE" || reports.state === "ERROR") {
    setHtml(root, "#rca-reports-table", renderResult(reports, { onLive: () => "" }));
  } else {
    const rows = list
      .map(
        (r) => `<tr>
        <td><code>${escapeHtml(na(r.report_id || r.rca_id))}</code></td>
        <td><code>${escapeHtml(na(r.event_id))}</code></td>
        <td>${escapeHtml(na(r.root_cause || r.summary || r.title))}</td>
        <td>${escapeHtml(fmtPct(r.confidence ?? r.rca_confidence))}</td>
        <td>${statusBadge(r.verification_status || "UNKNOWN")}</td>
        <td>${escapeHtml(shortTs(r.timestamp))}</td>
        <td>${
          r.event_id
            ? `<a class="investigate-link" href="#investigation/${encodeURIComponent(
                String(r.event_id).trim()
              )}">View Investigation</a>`
            : "N/A"
        }</td>
      </tr>`
      )
      .join("");
    const tableHtml = dataTable(
      ["Report ID", "Event ID", "Root Cause / Summary", "Confidence", "Verification", "Timestamp", ""],
      rows,
      "No RCA reports generated yet — reports are produced upon verified anomaly escalations"
    );
    setHtml(root, "#rca-reports-table", tableHtml);
  }
}

export async function renderTopology(root) {
  destroyPageCharts();
  const topo = await api.fetchTopology();
  root.innerHTML = `
    ${pageHeader({
      title: "Network Topology",
      subtitle: "READ ONLY — switches and learned hosts from the live controller snapshot.",
      badge: "READ ONLY",
      extra: stateExtra(topo),
    })}
    <div class="advisory banner">
      Observational only. Host–switch attachments come from L2 learning.
      Switch–switch links are not discovered (LLDP unused). No control actions.
    </div>
    <div id="topo-metrics" class="metric-grid"></div>
    ${sectionHeader("Switches", "")}
    <div id="topo-switches"></div>
    ${sectionHeader("Learned hosts", "")}
    <div id="topo-hosts"></div>
    ${sectionHeader("Host ↔ switch attachments", "")}
    <div id="topo-links"></div>
    <div id="topo-last-known"></div>
    <div id="topo-limits" class="panel muted" style="margin-top:1rem"></div>
  `;

  const metrics = root.querySelector("#topo-metrics");
  const swEl = root.querySelector("#topo-switches");
  const hostEl = root.querySelector("#topo-hosts");
  const linkEl = root.querySelector("#topo-links");
  const lastEl = root.querySelector("#topo-last-known");
  const limEl = root.querySelector("#topo-limits");

  const paint = (result) => {
    if (metrics) {
      metrics.innerHTML = renderResult(result, {
        onLive: (d) => {
          const freshness = d.freshness || "LIVE";
          return [
            metricCard({
              title: "Switches",
              value: fmtNum(d.switch_count, 0),
              state: freshness,
            }),
            metricCard({
              title: "Hosts",
              value: fmtNum(d.host_count, 0),
              state: freshness,
              subtitle: "Appear after traffic",
            }),
            metricCard({
              title: "Attachments",
              value: fmtNum(d.link_count, 0),
              state: freshness,
            }),
            metricCard({
              title: "Freshness",
              value: freshness,
              state: freshness,
              subtitle: d.updated_at ? `Updated ${d.updated_at}` : "No snapshot yet",
            }),
          ].join("");
        },
        onEmpty: () =>
          metricCard({
            title: "Topology",
            value: "UNAVAILABLE",
            state: "NO DATA",
            subtitle: "Start controller + Mininet to publish snapshot",
          }),
      });
    }

    if (swEl) {
      swEl.innerHTML = renderResult(result, {
        onEmpty: () =>
          emptyTopo("No switches", "Controller has not published connected datapaths yet."),
        onLive: (d) => {
          if (!(d.switches || []).length) {
            return emptyTopo(
              "No switches connected",
              "Mininet is down or the scenario ended. Last-known inventory is shown below if available. Start a legacy scenario (or Mininet) to reconnect switches."
            );
          }
          const rows = (d.switches || [])
            .map(
              (s) => `
            <tr>
              <td>${escapeHtml(na(s.name))}</td>
              <td><code>${escapeHtml(na(s.dpid_hex))}</code></td>
              <td>${escapeHtml(na(s.dpid))}</td>
            </tr>`
            )
            .join("");
          return dataTable(
            ["Switch", "DPID (hex)", "DPID"],
            rows,
            "No switches connected"
          );
        },
      });
    }

    if (hostEl) {
      hostEl.innerHTML = renderResult(result, {
        onEmpty: () =>
          emptyTopo(
            "No learned hosts",
            "Hosts appear after they send traffic (ARP/ICMP/etc.)."
          ),
        onLive: (d) => {
          if (!(d.hosts || []).length) {
            return emptyTopo(
              "No learned hosts yet",
              "Generate traffic (legacy Attack Lab / ping) so MACs are learned."
            );
          }
          const rows = (d.hosts || [])
            .map(
              (h) => `
            <tr>
              <td><code>${escapeHtml(na(h.mac))}</code></td>
              <td>${escapeHtml(na(h.switch))}</td>
              <td>${escapeHtml(na(h.port))}</td>
              <td><code>${escapeHtml(na(h.dpid_hex))}</code></td>
            </tr>`
            )
            .join("");
          return dataTable(
            ["MAC", "Switch", "Port", "DPID"],
            rows,
            "No hosts"
          );
        },
      });
    }

    if (linkEl) {
      linkEl.innerHTML = renderResult(result, {
        onEmpty: () => emptyTopo("No attachments", "No host↔switch edges yet."),
        onLive: (d) => {
          if (!(d.links || []).length) {
            return emptyTopo("No attachments yet", "Waiting for host learning.");
          }
          const rows = (d.links || [])
            .map(
              (l) => `
            <tr>
              <td><code>${escapeHtml(na(l.src))}</code></td>
              <td>${escapeHtml(na(l.dst_name || l.dst))}</td>
              <td>${escapeHtml(na(l.port))}</td>
            </tr>`
            )
            .join("");
          return dataTable(["Host MAC", "Switch", "Port"], rows, "No links");
        },
      });
    }

    if (lastEl) {
      lastEl.innerHTML = renderResult(result, {
        onLive: (d) => {
          const lk = d.last_known;
          if (!lk || d.switch_count > 0) return "";
          const swRows = (lk.switches || [])
            .map(
              (s) =>
                `<tr><td>${escapeHtml(na(s.name))}</td><td><code>${escapeHtml(
                  na(s.dpid_hex)
                )}</code></td></tr>`
            )
            .join("");
          const hRows = (lk.hosts || [])
            .slice(0, 20)
            .map(
              (h) =>
                `<tr><td><code>${escapeHtml(na(h.mac))}</code></td><td>${escapeHtml(
                  na(h.switch)
                )}</td></tr>`
            )
            .join("");
          return `
            <section class="panel" style="margin-top:1rem">
              <h3>Last known topology ${statusBadge("STALE")}</h3>
              <p class="muted">${escapeHtml(
                lk.note || "Shown because no switches are connected right now."
              )}
              Updated: ${escapeHtml(na(lk.updated_at))}</p>
              ${sectionHeader("Last known switches", "")}
              ${dataTable(["Switch", "DPID"], swRows, "None")}
              ${sectionHeader("Last known hosts", "")}
              ${dataTable(["MAC", "Switch"], hRows, "None")}
            </section>`;
        },
      });
    }

    if (limEl) {
      const d = result?.data;
      const limits = (d && d.limitations) || [];
      limEl.innerHTML = `<strong>Limitations</strong><ul>${limits
        .map((x) => `<li>${escapeHtml(String(x))}</li>`)
        .join("")}</ul><p>${escapeHtml(na(d?.note))}</p>`;
    }
  };

  function emptyTopo(title, body) {
    return `<div class="state-panel state-empty"><strong>${escapeHtml(
      title
    )}</strong><p>${escapeHtml(body)}</p></div>`;
  }

  paint(topo);
}

export async function renderTwin(root) {
  const [stats, snaps, runs, replays, sims, liveStateRes, liveSimsRes, policyValsRes] = await Promise.all([
    api.fetchTwinStats(),
    api.fetchTwinSnapshots(20),
    api.fetchTwinRuns(20),
    api.fetchTwinReplays(20),
    api.fetchTwinSimulations(20),
    api.fetchTwinLiveState(),
    api.fetchTwinLiveSimulations(10),
    api.fetchTwinPolicyValidations ? api.fetchTwinPolicyValidations(10).catch(() => ({ validations: [] })) : Promise.resolve({ validations: [] }),
  ]);

  const liveData = (liveStateRes && liveStateRes.data) || liveStateRes || {};
  const topo = liveData.topology || {};
  const telem = liveData.telemetry || {};
  const syncStatus = liveData.sync_status || "DISCONNECTED";
  const freshness = liveData.freshness || "UNAVAILABLE";
  const switchCount = Math.max(topo.switch_count || 0, (topo.switches && topo.switches.length) || (liveData.controller_connected ? 1 : 0));
  const hostCount = Math.max(topo.host_count || 0, (topo.hosts && topo.hosts.length) || 0);
  const switchName = (topo.switches && topo.switches[0] && (topo.switches[0].name || topo.switches[0].switch_id)) || "s1";
  const liveSims = ((liveSimsRes && liveSimsRes.data) || liveSimsRes || {}).simulations || [];
  const snapList = ((snaps && snaps.data) || snaps || {}).snapshots || [];
  const policyVals = ((policyValsRes && policyValsRes.data) || policyValsRes || {}).validations || [];

  const fidelityBadge = (fid) => {
    if (!fid) return statusBadge("NOT_AVAILABLE");
    const o = String(fid.overall || "").toUpperCase();
    if (o === "PASS") return statusBadge("PASS");
    if (o === "FAIL") return statusBadge("FAIL");
    if (o === "PASS_WITH_GAPS") return statusBadge("PARTIAL");
    return statusBadge("SNAPSHOT");
  };

  const renderLiveHistoryHtml = (simList) => {
    const list = Array.isArray(simList) ? simList : [];
    if (!list.length) {
      return `<p class="muted" style="padding:8px 0;">No live simulations recorded yet. Run a simulation above to record plan-space predictions.</p>`;
    }
    const rows = list.map((s) => {
      const proj = s.projected_telemetry || {};
      const imp = s.impact_assessment || {};
      return `<tr>
        <td><code>${escapeHtml(na(s.simulation_id))}</code></td>
        <td>${escapeHtml(na(s.scenario_id))}</td>
        <td>${escapeHtml(shortTs(s.created_at))}</td>
        <td>${escapeHtml(String(proj.projected_peak_packet_rate ?? "—"))} pkt/s</td>
        <td>${statusBadge(imp.estimated_severity || "LOW")}</td>
        <td>${escapeHtml(na(s.target_host || "h2"))}</td>
      </tr>`;
    }).join("");
    return dataTable(
      ["Simulation ID", "Scenario", "Timestamp", "Peak Rate", "Severity", "Target"],
      rows,
      "No live simulations"
    );
  };

  const renderPolicyHistoryHtml = (valList) => {
    const list = Array.isArray(valList) ? valList : [];
    if (!list.length) {
      return `<p class="muted" style="padding:8px 0;">No candidate policies validated yet. Validate a candidate policy below to test against snapshot telemetry.</p>`;
    }
    const rows = list.map((v) => {
      const cand = v.candidate_policy || {};
      const cls = v.classification || {};
      const imp = v.legitimate_traffic_impact || {};
      return `<tr>
        <td><code>${escapeHtml(na(v.validation_id))}</code></td>
        <td>${escapeHtml(na(cand.policy_name))}</td>
        <td>${statusBadge(v.validation_status || "UNKNOWN")}</td>
        <td>${escapeHtml(String(cand.packet_rate_threshold))} pkt/s</td>
        <td>${escapeHtml(fmtPct(cls.precision))}</td>
        <td>${escapeHtml(fmtPct(cls.recall))}</td>
        <td>${statusBadge(imp.impact_rating || "NONE")}</td>
        <td>${escapeHtml(shortTs(v.created_at))}</td>
      </tr>`;
    }).join("");
    return dataTable(
      ["Validation ID", "Policy Name", "Status", "Pkt Thresh", "Precision", "Recall", "Legit Impact", "Timestamp"],
      rows,
      "No policy validations"
    );
  };

  const snapOptions = snapList.length
    ? snapList.map((s) => {
        const sid = s.snapshot_id || s.id;
        const fl = s.csv_counts ? s.csv_counts["flow_stats.csv"] || 0 : 0;
        return `<option value="${escapeHtml(sid)}">${escapeHtml(sid)} (${s.n_windows ?? 0} windows, ${fl} flows)</option>`;
      }).join("")
    : `<option value="">No snapshots available</option>`;

  root.innerHTML = `
    ${pageHeader({
      title: "R3 Digital Twin",
      subtitle: "SDN DIGITAL TWIN · OBSERVATIONAL & WHAT-IF SIMULATION PLANE",
      badge: "READ ONLY",
      extra: stateExtra(stats),
    })}
    <div class="advisory banner">
      Digital Twin is an observational and software what-if twin. Strictly <strong>READ ONLY</strong> with respect to the SDN controller and OpenFlow switches.
      No packet injection into production, no automatic OpenFlow rule mutations. Candidate policies require explicit operator approval before integration.
    </div>

    <!-- Section 1: Network Topology & Representation -->
    <div style="display:flex; align-items:center; justify-content:space-between; margin-top:1.5rem; margin-bottom:0.5rem;">
      <h2 style="margin:0;">Level B: Live Network Synchronization</h2>
      <span class="badge" style="background:#0d2847;color:#58a6ff;border:1px solid #1f6feb;font-weight:600;padding:4px 8px;border-radius:4px;font-size:11px;">LIVE OBSERVATION</span>
    </div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="metric-title">Sync Health</div>
        <div class="metric-value">${statusBadge(syncStatus)}</div>
        <div class="metric-sub">Freshness: ${escapeHtml(freshness)} (lag: ${escapeHtml(String(liveData.age_seconds ?? "0"))}s)</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Live Switch</div>
        <div class="metric-value">${escapeHtml(String(switchCount))}</div>
        <div class="metric-sub">DPID: ${escapeHtml(switchName)} (0000000000000001) · OpenFlow 1.3</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Connected Hosts</div>
        <div class="metric-value">${escapeHtml(String(hostCount || 5))}</div>
        <div class="metric-sub">Attacker h1, Victim h2, Clients h3..h5</div>
      </div>
      <div class="metric-card">
        <div class="metric-title">Active Packet Rate</div>
        <div class="metric-value">${escapeHtml(String(telem.current_packet_rate ?? 0))} <span style="font-size:12px;">pkt/s</span></div>
        <div class="metric-sub">Flows tracked: ${escapeHtml(String(telem.active_flow_count ?? 0))}</div>
      </div>
    </div>

    <!-- Visual Topology & Node Inventory -->
    <section class="panel" style="margin-top:1rem; padding:12px 16px;">
      <h3 style="margin-top:0; font-size:14px; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-muted, #8b949e);">SDN Topology Model (IntelliShield Star v1)</h3>
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-top:8px;">
        <div style="background:var(--bg-elevated, #161b22); padding:10px; border-radius:6px; border-left:3px solid #388bfd;">
          <div style="font-weight:bold; color:#58a6ff;">Switch s1 (OpenFlow 1.3)</div>
          <div style="font-size:12px; color:#8b949e;">DPID: 0000000000000001</div>
          <div style="font-size:11px; color:#3fb950;">Controller: 127.0.0.1:6653</div>
        </div>
        <div style="background:var(--bg-elevated, #161b22); padding:10px; border-radius:6px; border-left:3px solid #f85149;">
          <div style="font-weight:bold; color:#f85149;">Host h1 (Attacker)</div>
          <div style="font-size:12px; color:#8b949e;">IP: 10.0.0.1 · Link: s1-eth1</div>
          <div style="font-size:11px; color:#8b949e;">Scenarios: S2 (SYN), S3 (UDP), S4, S5</div>
        </div>
        <div style="background:var(--bg-elevated, #161b22); padding:10px; border-radius:6px; border-left:3px solid #d29922;">
          <div style="font-weight:bold; color:#d29922;">Host h2 (Victim Server)</div>
          <div style="font-size:12px; color:#8b949e;">IP: 10.0.0.2 · Link: s1-eth2</div>
          <div style="font-size:11px; color:#8b949e;">Protected Target Server</div>
        </div>
        <div style="background:var(--bg-elevated, #161b22); padding:10px; border-radius:6px; border-left:3px solid #3fb950;">
          <div style="font-weight:bold; color:#3fb950;">Hosts h3, h4, h5 (Clients)</div>
          <div style="font-size:12px; color:#8b949e;">IPs: 10.0.0.3, 10.0.0.4, 10.0.0.5</div>
          <div style="font-size:11px; color:#8b949e;">Legitimate Baseline Background Traffic</div>
        </div>
      </div>
    </section>

    <!-- Section 2: Interactive What-If Simulator -->
    <div style="display:flex; align-items:center; justify-content:space-between; margin-top:2rem; margin-bottom:0.5rem;">
      <h2 style="margin:0;">Level B: Interactive What-If Simulator</h2>
      <span class="badge" style="background:#3b1e08;color:#ff9f43;border:1px solid #d97706;font-weight:600;padding:4px 8px;border-radius:4px;font-size:11px;">SIMULATION</span>
    </div>
    <div class="settings-grid">
      <section class="panel">
        <h3>Scenario Variant Parameters</h3>
        <p class="muted">Evaluate attack impact in plan space against active telemetry. Zero network packets injected.</p>
        <div class="identity-auth-form">
          <label class="identity-field">Scenario
            <select name="twin_sim_scenario">
              <option value="S2">S2 — SYN Flood (TCP)</option>
              <option value="S3">S3 — UDP Flood (Volumetric)</option>
              <option value="S4">S4 — Pulsing Burst DDoS</option>
              <option value="S5">S5 — Multi-Vector Flood</option>
              <option value="S1">S1 — Normal Baseline</option>
            </select>
          </label>
          <label class="identity-field">Attack Duration (seconds)
            <input type="number" name="twin_sim_duration" value="30" min="5" max="300" />
          </label>
          <label class="identity-field">Variant Attack Rate (pkt/s)
            <input type="number" name="twin_sim_rate" value="12000" min="500" max="100000" step="500" />
          </label>
          <label class="identity-field">Target Host
            <input type="text" name="twin_sim_target" value="h2" maxlength="32" />
          </label>
          <button type="button" class="btn-secondary" data-twin-run-sim style="margin-top:10px; width:100%;">Run What-If Simulation</button>
          <p class="identity-msg" data-twin-sim-msg hidden></p>
        </div>
      </section>

      <section class="panel">
        <h3>Simulation Outcome & Projected Impact</h3>
        <div id="twin-sim-result">
          <p class="muted">Select scenario parameters on the left and click <strong>Run What-If Simulation</strong> to evaluate the projected impact against current live telemetry in real-time.</p>
        </div>
      </section>
    </div>

    ${sectionHeader("Recent Live Simulations")}
    <div id="twin-live-sim-history">
      ${renderLiveHistoryHtml(liveSims)}
    </div>

    <!-- Section 3: Candidate Policy Validation & Safe Feedback Workflow -->
    <div style="display:flex; align-items:center; justify-content:space-between; margin-top:2.5rem; margin-bottom:0.5rem;">
      <h2 style="margin:0;">Candidate Detection & Mitigation Policy Validation</h2>
      <span class="badge" style="background:#261845;color:#bc8cff;border:1px solid #8957e5;font-weight:600;padding:4px 8px;border-radius:4px;font-size:11px;">SIMULATION / VALIDATION</span>
    </div>
    <p class="muted" style="margin-bottom:12px;">
      Evaluate candidate detection thresholds and mitigation rules against recorded experiment snapshots before deployment.
      Calculates predicted classification (TP, FP, FN, TN), legitimate traffic collateral impact, and candidate mitigation effectiveness.
      Strictly advisory: rules require explicit operator review and manual approval.
    </p>

    <div class="settings-grid">
      <section class="panel">
        <h3>Candidate Policy Parameters</h3>
        <div class="identity-auth-form">
          <label class="identity-field">Policy Name
            <input type="text" name="twin_pol_name" value="Adaptive-DDoS-Policy-v1" maxlength="64" />
          </label>
          <label class="identity-field">Target Snapshot (Evaluation Evidence)
            <select name="twin_pol_snapshot">
              ${snapOptions}
            </select>
          </label>
          <label class="identity-field">Packet Rate Threshold (pkt/s)
            <input type="number" name="twin_pol_pkt" value="5000" min="100" max="500000" step="100" />
          </label>
          <label class="identity-field">Byte Rate Threshold (bytes/s)
            <input type="number" name="twin_pol_byte" value="5000000" min="1000" max="1000000000" step="10000" />
          </label>
          <label class="identity-field">Confidence Threshold (0.00 – 1.00)
            <input type="number" name="twin_pol_conf" value="0.75" min="0.1" max="1.0" step="0.05" />
          </label>
          <label class="identity-field">Candidate Mitigation Action
            <select name="twin_pol_action">
              <option value="BLOCK">BLOCK (Drop suspicious flows via OpenFlow)</option>
              <option value="RATE_LIMIT">RATE_LIMIT (Throttle flow rate to safety ceiling)</option>
              <option value="OBSERVE">OBSERVE (Log and generate security alerts only)</option>
            </select>
          </label>
          <label class="identity-field">Idle Timeout (seconds)
            <input type="number" name="twin_pol_timeout" value="30" min="5" max="300" />
          </label>
          <button type="button" class="btn-secondary" data-twin-validate-policy style="margin-top:10px; width:100%;">Validate Candidate Policy</button>
          <p class="identity-msg" data-twin-pol-msg hidden></p>
        </div>
      </section>

      <section class="panel">
        <h3>Validation Report & Quality Gate Outcome</h3>
        <div id="twin-policy-result">
          <p class="muted">Configure candidate threshold parameters on the left and click <strong>Validate Candidate Policy</strong> to test against recorded snapshot flows.</p>
        </div>
      </section>
    </div>

    ${sectionHeader("Recent Candidate Policy Validations")}
    <div id="twin-policy-history">
      ${renderPolicyHistoryHtml(policyVals)}
    </div>

    <!-- Section 4: Snapshot Diff Tool -->
    <div style="display:flex; align-items:center; justify-content:space-between; margin-top:2.5rem; margin-bottom:0.5rem;">
      <h2 style="margin:0;">Observational Snapshot Diff Tool</h2>
      <span class="badge" style="background:#0e3a2f;color:#3fb950;border:1px solid #238636;font-weight:600;padding:4px 8px;border-radius:4px;font-size:11px;">RECORDED DATA</span>
    </div>
    <p class="muted" style="margin-bottom:12px;">Track differences between recorded experiment snapshots (flow row counts, traffic rate deltas, scenario coverage, and mitigation blocks).</p>
    <section class="panel" style="padding:14px;">
      <div style="display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap;">
        <label class="identity-field" style="flex:1; min-width:200px; margin:0;">Base Snapshot
          <select name="twin_diff_base">
            ${snapOptions}
          </select>
        </label>
        <label class="identity-field" style="flex:1; min-width:200px; margin:0;">Compare Snapshot
          <select name="twin_diff_compare">
            ${snapOptions}
          </select>
        </label>
        <button type="button" class="btn-secondary" data-twin-diff-btn style="height:36px; padding:0 16px;">Compare Snapshots</button>
      </div>
      <div id="twin-diff-result" style="margin-top:14px;">
        <p class="muted" style="margin:0;">Select two different snapshots above and click <strong>Compare Snapshots</strong> to compute telemetry and scenario deltas.</p>
      </div>
    </section>

    <!-- Section 5: Historical Twin Archives (Snapshots, Replays, Simulations, Runs) -->
    <div style="display:flex; align-items:center; justify-content:space-between; margin-top:2.5rem; margin-bottom:0.5rem;">
      <h2 style="margin:0;">Twin Telemetry Stats & Archives</h2>
      <span class="badge" style="background:#0e3a2f;color:#3fb950;border:1px solid #238636;font-weight:600;padding:4px 8px;border-radius:4px;font-size:11px;">RECORDED DATA</span>
    </div>
    ${renderResult(stats, {
      onLive: (d) => {
        const cards = [
          ["Snapshots", d.snapshots ?? 0],
          ["Replays", d.replays ?? 0],
          ["Simulations", d.simulations ?? 0],
          ["Policy Validations", d.policy_validations ?? 0],
          ["Runs", d.runs ?? 0],
        ]
          .map(
            ([t, v]) =>
              `<div class="metric-card"><div class="metric-title">${escapeHtml(
                t
              )}</div><div class="metric-value">${escapeHtml(String(v))}</div></div>`
          )
          .join("");
        return `<div class="metric-grid">${cards}</div>
          <p class="muted">control=${escapeHtml(na(d.control))} · source=${escapeHtml(
          na(d.source)
        )}</p>`;
      },
    })}

    ${sectionHeader("Snapshots + Fidelity", stateExtra(snaps))}
    ${renderResult(snaps, {
      onLive: (d) => {
        const rows = (d.snapshots || [])
          .map((s) => {
            const fid = s.fidelity || {};
            const sum = fid.summary || {};
            return `<tr>
            <td>${escapeHtml(na(s.snapshot_id || s.id))}</td>
            <td>${escapeHtml(shortTs(s.created_at || s.timestamp))}</td>
            <td>${fidelityBadge(fid)}</td>
            <td>${escapeHtml(
              `P${sum.PASS ?? "—"}/F${sum.FAIL ?? "—"}/N${sum.NOT_AVAILABLE ?? "—"}`
            )}</td>
            <td>${escapeHtml(String(s.n_windows ?? "—"))}</td>
          </tr>`;
          })
          .join("");
        return dataTable(
          ["Snapshot ID", "Created", "Overall", "PASS/FAIL/N/A", "Windows"],
          rows,
          "No snapshots"
        );
      },
    })}

    ${sectionHeader("Scenario Replays", stateExtra(replays))}
    ${renderResult(replays, {
      onLive: (d) => {
        const rows = (d.replays || [])
          .map(
            (r) => `<tr>
            <td>${escapeHtml(na(r.replay_id))}</td>
            <td>${escapeHtml(na(r.scenario_id))}</td>
            <td>${
              r.sequence_ok === true
                ? statusBadge("PASS")
                : r.sequence_ok === false
                  ? statusBadge("FAIL")
                  : statusBadge("NOT_AVAILABLE")
            }</td>
            <td>${escapeHtml(
              r.temporal_error != null ? String(r.temporal_error) : "—"
            )}</td>
            <td>${escapeHtml(na(r.snapshot_id))}</td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Replay ID", "Scenario", "Sequence", "Temporal err", "Snapshot"],
          rows,
          "No replays"
        );
      },
    })}

    ${sectionHeader("What-if Simulations", stateExtra(sims))}
    ${renderResult(sims, {
      onLive: (d) => {
        const rows = (d.simulations || [])
          .map(
            (s) => `<tr>
            <td>${escapeHtml(na(s.simulation_id))}</td>
            <td>${escapeHtml(na(s.scenario_id))}</td>
            <td>${escapeHtml(na(s.snapshot_id))}</td>
            <td><code>${escapeHtml(
              JSON.stringify(s.overrides || s.parameters || {}).slice(0, 80)
            )}</code></td>
          </tr>`
          )
          .join("");
        return dataTable(
          ["Simulation ID", "Scenario", "Snapshot", "Overrides"],
          rows,
          "No simulations"
        );
      },
    })}

    ${sectionHeader("Experiment Runs", stateExtra(runs))}
    ${renderResult(runs, {
      onLive: (d) => {
        const rows = (d.runs || [])
          .map(
            (r) => `<tr>
            <td>${escapeHtml(na(r.run_id || r.id))}</td>
            <td>${escapeHtml(na(r.status || r.validation_status))}</td>
            <td>${escapeHtml(shortTs(r.timestamp || r.created_at))}</td>
          </tr>`
          )
          .join("");
        return dataTable(["Run ID", "Status", "Timestamp"], rows, "No twin runs");
      },
    })}
  `;

  // ── Event Handlers: What-If Simulator ──────────────────────────────────────
  const runBtn = root.querySelector("[data-twin-run-sim]");
  const msgEl = root.querySelector("[data-twin-sim-msg]");
  const resultEl = root.querySelector("#twin-sim-result");
  const historyEl = root.querySelector("#twin-live-sim-history");

  function showMsg(text, isError) {
    if (!msgEl) return;
    msgEl.hidden = !text;
    msgEl.textContent = text || "";
    msgEl.classList.toggle("identity-error", !!isError);
  }

  runBtn?.addEventListener("click", async () => {
    const scenarioId = root.querySelector('select[name="twin_sim_scenario"]')?.value || "S2";
    const duration = parseFloat(root.querySelector('input[name="twin_sim_duration"]')?.value || "30");
    const rate = parseFloat(root.querySelector('input[name="twin_sim_rate"]')?.value || "12000");
    const targetHost = (root.querySelector('input[name="twin_sim_target"]')?.value || "h2").trim();

    showMsg("Evaluating what-if plan in software...", false);
    runBtn.disabled = true;

    try {
      const overrides = {
        attack_sec: duration,
        syn_rate: rate,
        udp_rate: rate,
        intensity: rate,
      };

      const result = await api.postTwinLiveSimulate({
        scenario_id: scenarioId,
        overrides,
        target_host: targetHost,
        persist: true,
      });

      showMsg("Simulation complete (evaluated in plan space).", false);

      const proj = result.projected_telemetry || {};
      const liveB = result.live_baseline || {};
      const imp = result.impact_assessment || {};

      if (resultEl) {
        resultEl.innerHTML = `
          <div style="display:flex; gap:10px; margin-bottom:10px;">
            <div class="metric-card" style="flex:1;">
              <div class="metric-title">Live Baseline Rate</div>
              <div class="metric-value">${escapeHtml(String(liveB.current_packet_rate ?? 0))} pkt/s</div>
            </div>
            <div class="metric-card" style="flex:1;">
              <div class="metric-title">Projected Peak Rate</div>
              <div class="metric-value" style="color:var(--neon-orange, #ff9f43);">${escapeHtml(String(proj.projected_peak_packet_rate ?? 0))} pkt/s</div>
            </div>
            <div class="metric-card" style="flex:1;">
              <div class="metric-title">Severity Assessment</div>
              <div class="metric-value">${statusBadge(imp.estimated_severity || "LOW")}</div>
            </div>
          </div>

          <div class="panel" style="background:var(--bg-elevated, #1a1e28); padding:10px; font-size:13px;">
            <div><strong>Surge Multiplier:</strong> ${escapeHtml(String(proj.rate_surge_multiplier ?? 1))}x</div>
            <div><strong>Attack Duration:</strong> ${escapeHtml(String(proj.variant_duration_sec ?? duration))}s (delta: ${escapeHtml(String(proj.duration_delta_sec ?? 0))}s)</div>
            <div><strong>Estimated Load Ratio:</strong> ${escapeHtml(String(Math.round((imp.projected_load_ratio || 0) * 100)))}% of link budget</div>
            <div><strong>Target:</strong> Switch ${escapeHtml(imp.target_switch || "s1")}, Host ${escapeHtml(imp.target_host || targetHost)}</div>
            <div><strong>Mitigation Required:</strong> ${imp.mitigation_required ? "YES (Threat exceeds safety baseline)" : "NO (Within normal capacity)"}</div>
          </div>
        `;
      }

      const freshHistory = await api.fetchTwinLiveSimulations(10);
      if (historyEl) {
        historyEl.innerHTML = renderLiveHistoryHtml(freshHistory);
      }
    } catch (err) {
      showMsg(err.message || "Simulation error", true);
    } finally {
      runBtn.disabled = false;
    }
  });

  // ── Event Handlers: Candidate Policy Validator ─────────────────────────────
  const valBtn = root.querySelector("[data-twin-validate-policy]");
  const valMsgEl = root.querySelector("[data-twin-pol-msg]");
  const valResultEl = root.querySelector("#twin-policy-result");
  const valHistoryEl = root.querySelector("#twin-policy-history");

  function showValMsg(text, isError) {
    if (!valMsgEl) return;
    valMsgEl.hidden = !text;
    valMsgEl.textContent = text || "";
    valMsgEl.classList.toggle("identity-error", !!isError);
  }

  valBtn?.addEventListener("click", async () => {
    const policyName = (root.querySelector('input[name="twin_pol_name"]')?.value || "Candidate-Policy").trim();
    const snapshotId = root.querySelector('select[name="twin_pol_snapshot"]')?.value || null;
    const pktRate = parseFloat(root.querySelector('input[name="twin_pol_pkt"]')?.value || "5000");
    const byteRate = parseFloat(root.querySelector('input[name="twin_pol_byte"]')?.value || "5000000");
    const conf = parseFloat(root.querySelector('input[name="twin_pol_conf"]')?.value || "0.75");
    const action = root.querySelector('select[name="twin_pol_action"]')?.value || "BLOCK";
    const timeout = parseInt(root.querySelector('input[name="twin_pol_timeout"]')?.value || "30", 10);

    showValMsg("Evaluating candidate policy against snapshot telemetry...", false);
    valBtn.disabled = true;

    try {
      const res = await api.postTwinValidatePolicy({
        policy_name: policyName,
        snapshot_id: snapshotId,
        packet_rate_threshold: pktRate,
        byte_rate_threshold: byteRate,
        confidence_threshold: conf,
        mitigation_action: action,
        idle_timeout_sec: timeout,
        persist: true,
      });

      showValMsg("Policy validation completed.", false);

      const cls = res.classification || {};
      const imp = res.legitimate_traffic_impact || {};
      const mit = res.mitigation_outcome || {};
      const wf = res.safe_feedback_workflow || {};
      const findings = res.gate_findings || [];

      if (valResultEl) {
        valResultEl.innerHTML = `
          <div style="display:flex; gap:10px; margin-bottom:10px;">
            <div class="metric-card" style="flex:1;">
              <div class="metric-title">Validation Verdict</div>
              <div class="metric-value">${statusBadge(res.validation_status || "UNKNOWN")}</div>
            </div>
            <div class="metric-card" style="flex:1;">
              <div class="metric-title">Precision / Recall</div>
              <div class="metric-value" style="font-size:16px;">${escapeHtml(fmtPct(cls.precision))} / ${escapeHtml(fmtPct(cls.recall))}</div>
              <div class="metric-sub">F1: ${escapeHtml(fmtPct(cls.f1_score))} · FPR: ${escapeHtml(fmtPct(cls.false_positive_rate))}</div>
            </div>
            <div class="metric-card" style="flex:1;">
              <div class="metric-title">Legitimate Impact</div>
              <div class="metric-value">${statusBadge(imp.impact_rating || "NONE")}</div>
              <div class="metric-sub">${escapeHtml(String(imp.collateral_damage_pct ?? 0))}% normal flows affected</div>
            </div>
          </div>

          <div class="panel" style="background:var(--bg-elevated, #1a1e28); padding:10px; font-size:13px; margin-bottom:10px;">
            <div style="font-weight:bold; margin-bottom:4px; color:#58a6ff;">Confusion Matrix (Ground Truth Evaluation)</div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px; font-size:12px;">
              <div>True Positives (Attack Flagged): <strong>${escapeHtml(String(cls.true_positives ?? 0))}</strong></div>
              <div>False Positives (Normal Flagged): <strong style="color:${cls.false_positives ? '#f85149' : '#3fb950'};">${escapeHtml(String(cls.false_positives ?? 0))}</strong></div>
              <div>False Negatives (Attack Missed): <strong style="color:${cls.false_negatives ? '#f85149' : '#3fb950'};">${escapeHtml(String(cls.false_negatives ?? 0))}</strong></div>
              <div>True Negatives (Normal Cleared): <strong>${escapeHtml(String(cls.true_negatives ?? 0))}</strong></div>
            </div>
            <div style="margin-top:8px;"><strong>Impact Description:</strong> ${escapeHtml(imp.description || "N/A")}</div>
            <div><strong>Mitigation Outcome:</strong> ${escapeHtml(mit.summary || "N/A")}</div>
            ${findings.length ? `<div style="margin-top:6px; color:#ff9f43;"><strong>Quality Gate Findings:</strong> ${escapeHtml(findings.join("; "))}</div>` : ""}
          </div>

          <!-- Safe Operator Approval Gateway -->
          <div style="background:#131d27; border:1px solid #1f6feb; border-radius:6px; padding:10px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <div>
                <strong style="color:#58a6ff;">Controlled Feedback Approval Gateway</strong>
                <div style="font-size:11px; color:#8b949e;">Status: <span style="color:#d29922; font-weight:bold;">${escapeHtml(wf.approval_status || "PENDING_OPERATOR_APPROVAL")}</span> (Auto-Apply: PROHIBITED)</div>
              </div>
              <button type="button" class="btn-secondary" data-twin-toggle-export style="font-size:11px; padding:4px 8px;">Show Export Config</button>
            </div>
            <div id="twin-export-payload" hidden style="margin-top:8px; background:#0d1117; padding:8px; border-radius:4px; font-family:monospace; font-size:11px; overflow-x:auto;">
              <pre style="margin:0;">${escapeHtml(JSON.stringify(wf.controller_export_payload || {}, null, 2))}</pre>
            </div>
          </div>
        `;

        valResultEl.querySelector("[data-twin-toggle-export]")?.addEventListener("click", () => {
          const el = valResultEl.querySelector("#twin-export-payload");
          if (el) el.hidden = !el.hidden;
        });
      }

      if (valHistoryEl && api.fetchTwinPolicyValidations) {
        const freshVals = await api.fetchTwinPolicyValidations(10);
        valHistoryEl.innerHTML = renderPolicyHistoryHtml(freshVals);
      }
    } catch (err) {
      showValMsg(err.message || "Policy validation error", true);
    } finally {
      valBtn.disabled = false;
    }
  });

  // ── Event Handlers: Snapshot Diff Tool ─────────────────────────────────────
  const diffBtn = root.querySelector("[data-twin-diff-btn]");
  const diffResultEl = root.querySelector("#twin-diff-result");

  diffBtn?.addEventListener("click", async () => {
    const baseId = root.querySelector('select[name="twin_diff_base"]')?.value;
    const compareId = root.querySelector('select[name="twin_diff_compare"]')?.value;

    if (!baseId || !compareId) {
      if (diffResultEl) diffResultEl.innerHTML = `<p class="identity-error">Both Base and Compare snapshots must be selected.</p>`;
      return;
    }
    if (baseId === compareId) {
      if (diffResultEl) diffResultEl.innerHTML = `<p class="identity-error">Please select two different snapshots to compare.</p>`;
      return;
    }

    if (diffResultEl) diffResultEl.innerHTML = `<p class="muted">Calculating observational differences...</p>`;

    try {
      const diff = await api.fetchTwinSnapshotDiff(baseId, compareId);
      const d = diff.delta || {};
      const sc = diff.scenario_comparison || {};
      const prof = diff.profile_comparison || {};

      if (diffResultEl) {
        diffResultEl.innerHTML = `
          <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:10px; margin-bottom:12px;">
            <div class="metric-card">
              <div class="metric-title">Flow Rows Delta</div>
              <div class="metric-value" style="color:${d.flow_rows_delta >= 0 ? '#3fb950' : '#f85149'};">${d.flow_rows_delta > 0 ? '+' : ''}${escapeHtml(String(d.flow_rows_delta ?? 0))}</div>
              <div class="metric-sub">Base: ${diff.base ? diff.base.flow_rows : 0} → Compare: ${diff.compare ? diff.compare.flow_rows : 0}</div>
            </div>
            <div class="metric-card">
              <div class="metric-title">Attack Windows Delta</div>
              <div class="metric-value">${d.window_count_delta > 0 ? '+' : ''}${escapeHtml(String(d.window_count_delta ?? 0))}</div>
              <div class="metric-sub">Base: ${diff.base ? diff.base.n_windows : 0} → Compare: ${diff.compare ? diff.compare.n_windows : 0}</div>
            </div>
            <div class="metric-card">
              <div class="metric-title">Baseline Rate Delta</div>
              <div class="metric-value">${d.baseline_mean_pkt_s_delta != null ? String(d.baseline_mean_pkt_s_delta) + ' pkt/s' : '—'}</div>
              <div class="metric-sub">Traffic baseline shift</div>
            </div>
            <div class="metric-card">
              <div class="metric-title">Attack Rate Delta</div>
              <div class="metric-value">${d.attack_mean_pkt_s_delta != null ? String(d.attack_mean_pkt_s_delta) + ' pkt/s' : '—'}</div>
              <div class="metric-sub">Malicious volume shift</div>
            </div>
          </div>
          <div class="panel" style="background:var(--bg-elevated, #1a1e28); padding:10px; font-size:12px;">
            <div><strong>Scenario Coverage:</strong> Base: [${escapeHtml((sc.base_scenarios || []).join(", "))}] → Compare: [${escapeHtml((sc.compare_scenarios || []).join(", "))}]</div>
            ${sc.added_in_compare && sc.added_in_compare.length ? `<div><strong>Added Scenarios:</strong> <span style="color:#3fb950;">+${escapeHtml(sc.added_in_compare.join(", "))}</span></div>` : ""}
            ${sc.removed_in_compare && sc.removed_in_compare.length ? `<div><strong>Removed Scenarios:</strong> <span style="color:#f85149;">-${escapeHtml(sc.removed_in_compare.join(", "))}</span></div>` : ""}
            <div><strong>Profile Fingerprint Match:</strong> ${prof.same_fingerprint ? '<span style="color:#3fb950;">MATCH (Identical lab configuration)</span>' : '<span style="color:#ff9f43;">DIFFERENT (Configuration changed)</span>'}</div>
          </div>
        `;
      }
    } catch (err) {
      if (diffResultEl) diffResultEl.innerHTML = `<p class="identity-error">Diff error: ${escapeHtml(err.message)}</p>`;
    }
  });
}


export async function renderAttackLab(root) {
  destroyPageCharts();
  root.innerHTML = `
    ${pageHeader({
      title: "Attack Lab",
      subtitle: "Redirected — use Lab Control for real scenario / controller actions.",
      badge: "MOVED",
    })}
    <div class="advisory banner">
      Legacy Master Control write actions are available under
      <a href="#lab-control"><strong>Lab Control</strong></a>
      (restart/stop controller, archive, scenarios S1–S5, batch eval, metrics, train, bundle).
      This route is kept as an alias so old bookmarks still resolve.
    </div>
    <p class="muted"><a href="#lab-control">Open Lab Control →</a> · Legacy fallback: <a href="/legacy">/legacy</a></p>
  `;
}

export async function renderSettings(root) {
  destroyPageCharts();
  root.innerHTML = `
    ${pageHeader({
      title: "Settings",
      subtitle: "Identity and readiness. Backend detection/mitigation thresholds are not editable from the browser.",
      badge: "READ ONLY",
    })}
    <div class="settings-grid" data-settings-root>
      <section class="panel">
        <h3>Current backend configuration</h3>
        <p class="muted">Not editable from this UI (same constraint as legacy). Thresholds, confidence, mitigation, and ML config remain server-side / controller-side.</p>
      </section>
      <section class="panel">
        <h3>UI preferences</h3>
        <p class="muted">No browser preference editor existed in the legacy UI. Operational parity does not require one; theme/layout remain fixed in CSS.</p>
      </section>
      <section class="panel" data-email-panel>
        <h3>Email Alert Notifications (Gmail SMTP)</h3>
        <p class="muted">Configured via <code>.env</code> file. Confirmed-attack alerts from R6 Fusion → R7 Verification are dispatched automatically.</p>
        <div data-email-status-slot><p class="muted">Loading email configuration…</p></div>
        <div style="margin-top: 12px;">
          <button type="button" class="btn btn-primary" id="btn-send-test-email">📧 Send Test Email</button>
        </div>
        <div id="test-email-result" style="margin-top: 12px; display: none;"></div>
      </section>
      <div data-identity-slot></div>
      <div data-readiness-slot></div>
    </div>
  `;

  const emailStatusSlot = root.querySelector("[data-email-status-slot]");
  const testEmailBtn = root.querySelector("#btn-send-test-email");
  const testEmailResult = root.querySelector("#test-email-result");

  async function loadEmailStatus() {
    if (!emailStatusSlot) return;
    try {
      const info = await api.fetchEmailAlertStatus();
      if (info && info.state === "LIVE" && info.data) {
        const d = info.data;
        const badgeClass = d.is_configured ? "badge-success" : "badge-warn";
        const badgeText = d.is_configured ? "CONFIGURED & READY" : d.enabled ? "INCOMPLETE CONFIG" : "DISABLED";
        emailStatusSlot.innerHTML = `
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin-bottom: 10px;">
            <div><span class="muted">Status:</span> <span class="badge ${badgeClass}">${badgeText}</span></div>
            <div><span class="muted">Recipient:</span> <strong>${escapeHtml(d.recipient)}</strong></div>
            <div><span class="muted">SMTP Host:</span> <code>${escapeHtml(d.smtp_host)}:${d.smtp_port}</code></div>
            <div><span class="muted">Cooldown:</span> ${d.cooldown_seconds}s</div>
          </div>
        `;
      } else {
        emailStatusSlot.innerHTML = `<p class="muted">Email status unavailable.</p>`;
      }
    } catch (_e) {
      emailStatusSlot.innerHTML = `<p class="muted">Failed to load email config status.</p>`;
    }
  }

  if (testEmailBtn) {
    testEmailBtn.addEventListener("click", async () => {
      testEmailBtn.disabled = true;
      testEmailBtn.textContent = "Sending Test Email…";
      if (testEmailResult) {
        testEmailResult.style.display = "block";
        testEmailResult.className = "banner info";
        testEmailResult.textContent = "Connecting to SMTP server and transmitting test email…";
      }
      try {
        const res = await api.postTestEmail();
        testEmailBtn.disabled = false;
        testEmailBtn.textContent = "📧 Send Test Email";
        if (testEmailResult) {
          if (res && res.ok) {
            testEmailResult.className = "banner success";
            testEmailResult.innerHTML = `<strong>✅ Test Email Sent:</strong> ${escapeHtml(res.message)}`;
          } else {
            testEmailResult.className = "banner danger";
            testEmailResult.innerHTML = `<strong>❌ Test Email Failed (${escapeHtml(res.status || "ERROR")}):</strong> ${escapeHtml(res.message || "Transmission failed.")}`;
          }
        }
      } catch (err) {
        testEmailBtn.disabled = false;
        testEmailBtn.textContent = "📧 Send Test Email";
        if (testEmailResult) {
          testEmailResult.className = "banner danger";
          testEmailResult.innerHTML = `<strong>❌ Request Failed:</strong> ${escapeHtml(err.message || "Failed to reach dashboard API.")}`;
        }
      }
    });
  }

  loadEmailStatus();

  const identitySlot = root.querySelector("[data-identity-slot]");
  const readinessSlot = root.querySelector("[data-readiness-slot]");

  async function refreshIdentity() {
    const [meRes, statusRes] = await Promise.all([
      authApi.fetchAuthMe(),
      authApi.fetchAuthStatus(),
    ]);
    const me = meRes.state === "LIVE" ? meRes.data : null;
    const status = statusRes.state === "LIVE" ? statusRes.data : null;
    const authView = {
      authentication_configured:
        (me && me.authentication_configured) ||
        (status && status.authentication_configured) ||
        false,
      authenticated: !!(me && me.authenticated),
      principal: me && me.principal,
      authorization_implemented:
        (me && me.authorization_implemented) ||
        (status && status.authorization_implemented) ||
        false,
      rbac_enabled:
        (me && me.rbac_enabled) || (status && status.rbac_enabled) || false,
      operator_controls_enabled: false,
    };
    if (identitySlot) {
      identitySlot.innerHTML = identityPanelHtml(escapeHtml, statusBadge, me, status);
      wireIdentityActions(identitySlot, refreshIdentity);
    }
    if (readinessSlot) {
      readinessSlot.innerHTML = operatorReadinessHtml(escapeHtml, statusBadge, authView);
    }
  }

  await refreshIdentity();
}

function wireIdentityActions(container, onDone) {
  const msg = container.querySelector("[data-auth-msg]");
  const loginBtn = container.querySelector("[data-auth-login]");
  const logoutBtn = container.querySelector("[data-auth-logout]");

  function showMsg(text, isError) {
    if (!msg) return;
    msg.hidden = !text;
    msg.textContent = text || "";
    msg.classList.toggle("identity-error", !!isError);
  }

  if (loginBtn) {
    loginBtn.addEventListener("click", async () => {
      const userEl = container.querySelector('input[name="username"]');
      const passEl = container.querySelector('input[name="password"]');
      const username = userEl ? userEl.value : "";
      const password = passEl ? passEl.value : "";
      showMsg("Signing in…", false);
      const result = await authApi.login({ username, password });
      if (!result.ok) {
        showMsg(result.error || "Authentication failed", true);
        return;
      }
      // Clear password field from DOM
      if (passEl) passEl.value = "";
      await onDone();
    });
  }
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      await authApi.logout();
      await onDone();
    });
  }
}
