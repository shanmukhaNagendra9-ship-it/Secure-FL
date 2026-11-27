/**
 * Interactive SVG Charts & Heatmaps for SecureFL Dashboard.
 */
import { escapeHtml } from "./api.js";

const SVG_NS = "http://www.w3.org/2000/svg";

function svgEl(tag, attrs = {}) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    el.setAttribute(k, String(v));
  }
  return el;
}

export function renderDonutChart(threats) {
  const svg = document.getElementById("donut-chart");
  const legend = document.getElementById("donut-legend");
  if (!svg || !legend) return;

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const t of threats) {
    const sev =
      t.severity ||
      (t.confidence >= 0.88 ? "critical" : t.confidence >= 0.7 ? "high" : t.confidence >= 0.4 ? "medium" : "low");
    counts[sev] = (counts[sev] || 0) + 1;
  }

  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
  const colors = { critical: "#ef4444", high: "#f59e0b", medium: "#38bdf8", low: "#10b981" };

  svg.innerHTML = "";
  let angle = -Math.PI / 2;
  const cx = 80, cy = 80, r = 58, ir = 40;

  for (const [sev, val] of Object.entries(counts)) {
    if (!val) continue;
    const slice = (val / total) * Math.PI * 2;
    const end = angle + slice;
    const x1 = cx + r * Math.cos(angle), y1 = cy + r * Math.sin(angle);
    const x2 = cx + r * Math.cos(end), y2 = cy + r * Math.sin(end);
    const ix1 = cx + ir * Math.cos(end), iy1 = cy + ir * Math.sin(end);
    const ix2 = cx + ir * Math.cos(angle), iy2 = cy + ir * Math.sin(angle);
    const large = slice > Math.PI ? 1 : 0;

    svg.appendChild(
      svgEl("path", {
        d: `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2} L ${ix1} ${iy1} A ${ir} ${ir} 0 ${large} 0 ${ix2} ${iy2} Z`,
        fill: colors[sev],
      })
    );
    angle = end;
  }

  const label = svgEl("text", {
    x: cx,
    y: cy + 5,
    "text-anchor": "middle",
    fill: "var(--text-bright)",
    "font-size": 16,
    "font-weight": 800,
  });
  label.textContent = String(threats.length);
  svg.appendChild(label);

  legend.innerHTML = Object.entries(counts)
    .map(
      ([s, c]) =>
        `<div style="display:flex;justify-content:space-between;font-size:12.5px">
          <span style="display:flex;align-items:center;gap:7px">
            <span style="width:10px;height:10px;border-radius:3px;background:${colors[s]}"></span>
            <span style="text-transform:capitalize">${escapeHtml(s)}</span>
          </span>
          <strong style="color:var(--text-bright)">${c}</strong>
        </div>`
    )
    .join("");
}

export function renderFlConvergenceChart(rounds) {
  const svg = document.getElementById("fl-trend-svg");
  if (!svg) return;
  svg.innerHTML = "";
  if (!rounds || rounds.length === 0) {
    const t = svgEl("text", { x: 250, y: 105, "text-anchor": "middle", fill: "#94a3b8", "font-size": 12 });
    t.textContent = "Run a Flower FL round to visualize live convergence.";
    svg.appendChild(t);
    return;
  }

  const W = 500, H = 210, padL = 42, padR = 20, padT = 20, padB = 28;
  const minAcc = 0.5, maxAcc = 1.0;
  const xStep = (W - padL - padR) / Math.max(rounds.length - 1, 1);
  const yScale = (acc) => H - padB - ((Math.max(minAcc, Math.min(maxAcc, acc)) - minAcc) / (maxAcc - minAcc)) * (H - padT - padB);

  for (const level of [0.6, 0.75, 0.9, 1.0]) {
    const y = yScale(level);
    svg.appendChild(svgEl("line", { x1: padL, y1: y, x2: W - padR, y2: y, stroke: "rgba(148,163,184,0.2)", "stroke-dasharray": "3,3" }));
    const txt = svgEl("text", { x: padL - 6, y: y + 4, "text-anchor": "end", fill: "#94a3b8", "font-size": 10 });
    txt.textContent = `${Math.round(level * 100)}%`;
    svg.appendChild(txt);
  }

  const pts = rounds.map((r, i) => `${padL + i * xStep},${yScale(r.accuracy)}`);
  svg.appendChild(svgEl("path", { d: `M ${pts.join(" L ")}`, fill: "none", stroke: "#38bdf8", "stroke-width": 2.5 }));
  rounds.forEach((r, i) => {
    svg.appendChild(svgEl("circle", { cx: padL + i * xStep, cy: yScale(r.accuracy), r: 4, fill: "#7c3aed", stroke: "#fff", "stroke-width": 1.5 }));
  });
}

export function renderPrivacyGauge(used, total) {
  const svg = document.getElementById("gauge-svg");
  if (!svg) return;
  svg.innerHTML = "";
  const cx = 100, cy = 105, r = 70;
  const startA = Math.PI * 0.8, endA = Math.PI * 2.2;
  const frac = Math.min(Math.max(used / Math.max(total, 0.001), 0), 1);
  const color = frac > 0.8 ? "#ef4444" : frac > 0.5 ? "#f59e0b" : "#10b981";
  const arc = (s, e) => {
    const x1 = cx + r * Math.cos(s), y1 = cy + r * Math.sin(s);
    const x2 = cx + r * Math.cos(e), y2 = cy + r * Math.sin(e);
    const la = e - s > Math.PI ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${la} 1 ${x2} ${y2}`;
  };
  svg.appendChild(svgEl("path", { d: arc(startA, endA), fill: "none", stroke: "rgba(148,163,184,0.2)", "stroke-width": 14, "stroke-linecap": "round" }));
  if (frac > 0.005) {
    svg.appendChild(svgEl("path", { d: arc(startA, startA + frac * (endA - startA)), fill: "none", stroke: color, "stroke-width": 14, "stroke-linecap": "round" }));
  }
  const valTxt = svgEl("text", { x: cx, y: cy + 4, "text-anchor": "middle", fill: "var(--text-bright)", "font-size": 17, "font-weight": 800 });
  valTxt.textContent = `${used.toFixed(2)}`;
  svg.appendChild(valTxt);
}

export function renderBenchmarkBars(models) {
  const svg = document.getElementById("bench-svg");
  if (!svg) return;
  svg.innerHTML = "";
  if (!models || models.length === 0) {
    const t = svgEl("text", { x: 250, y: 110, "text-anchor": "middle", fill: "#94a3b8", "font-size": 12 });
    t.textContent = "Click 'Run Benchmark Suite' to evaluate LSTM, Random Forest & XGBoost.";
    svg.appendChild(t);
    return;
  }

  const barW = 36;
  models.forEach((m, idx) => {
    const gx = 55 + idx * 145;
    const accH = m.accuracy * 145;
    const f1H = m.f1_score * 145;
    svg.appendChild(svgEl("rect", { x: gx, y: 175 - accH, width: barW, height: accH, rx: 5, fill: "#7c3aed" }));
    svg.appendChild(svgEl("rect", { x: gx + barW + 8, y: 175 - f1H, width: barW, height: f1H, rx: 5, fill: "#38bdf8" }));
    const lbl = svgEl("text", { x: gx + barW, y: 196, "text-anchor": "middle", fill: "var(--text)", "font-size": 10.5 });
    lbl.textContent = m.model_name.split(" ")[0];
    svg.appendChild(lbl);
    const pct = svgEl("text", { x: gx + barW / 2, y: 168 - accH, "text-anchor": "middle", fill: "var(--text-bright)", "font-size": 10 });
    pct.textContent = `${(m.accuracy * 100).toFixed(1)}%`;
    svg.appendChild(pct);
  });
}
