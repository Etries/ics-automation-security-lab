#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Evaluation plots & stats (fixed):
- Normalizes Attack IDs (merges attack_13_main -> Attack 13)
- Generates Alerts-per-Attack bar chart (ONE bar per attack)
- Scatter plots, multiple regression, correlation table

Run:
  python3 eval_plots.py --csv /path/to/evaluation.csv --outdir figs
"""

import os, re, argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

plt.rcParams.update({
    "figure.dpi": 140,
    "font.size": 10,
    "axes.titlesize": 12,
    "axes.labelsize": 11
})

# ----------------------------- Utilities -----------------------------

ALIAS_MAP = {
    # collapse all these into a single "Attack 13"
    "attack_13_main": "attack_13",
    "attack_13-main": "attack_13",
    "Attack_13_main": "attack_13",
    "Attack 13 main": "attack_13",
    "A13_main": "A13",
    "A13 main": "A13",
    "A-13": "A13",
    "A 13": "A13",
}

def normalize_attack_id(value: str) -> str:
    """
    Convert any attack label variant into a clean display label: 'Attack N'.
    Examples that become 'Attack 13':
      'attack_13', 'attack_13_main', 'A13', 'A13_main', 'Attack 13 main'
    """
    x = str(value).strip()
    x = ALIAS_MAP.get(x, x)  # unify known aliases first

    # Try to extract the numeric part robustly
    # Accept forms: 'attack_07', 'attack_7', 'Attack 7', 'A07', 'A7', '7', etc.
    m = re.search(r'(\d+)', x)
    if not m:
        # If we truly can't parse a number, keep original (rare)
        return x

    n = int(m.group(1))
    return f"Attack {n:d}"

def ensure_col(df: pd.DataFrame, candidates, default=None):
    """Return the first existing column in candidates; otherwise create with default."""
    for c in candidates:
        if c in df.columns:
            return c
    if default is not None:
        df[default] = np.nan
        return default
    raise KeyError(f"None of the columns exist: {candidates}")

def standardize(a: np.ndarray) -> np.ndarray:
    a = np.asarray(a, float)
    return (a - a.mean()) / (a.std(ddof=0) + 1e-12)

def multiple_regression(X: np.ndarray, y: np.ndarray):
    # OLS closed-form
    beta = np.linalg.inv(X.T @ X) @ (X.T @ y)
    yhat = X @ beta
    resid = y - yhat
    rss = float(np.sum(resid**2))
    tss = float(np.sum((y - y.mean())**2))
    r2 = float(1 - rss / tss) if tss > 0 else np.nan
    return beta, yhat, resid, r2

def make_png_table(df, title, fname):
    fig = plt.figure(figsize=(8, 0.6 + 0.35*len(df)))
    ax = fig.add_subplot(111); ax.axis('off')
    ax.text(0, 1.05, title, fontsize=12, fontweight='bold', va='bottom', ha='left')
    tbl = ax.table(cellText=df.values, colLabels=df.columns, loc='center', cellLoc='center')
    tbl.auto_set_font_size(False); tbl.set_fontsize(9); tbl.scale(1, 1.2)
    for (r, c), cell in tbl.get_celld().items():
        if r == 0:
            cell.set_facecolor("#343a40"); cell.set_text_props(color="white", weight='bold')
        else:
            cell.set_facecolor("#f1f3f5")
    plt.savefig(fname, bbox_inches="tight"); plt.close()

def linfit(x, y):
    x = np.asarray(x, float); y = np.asarray(y, float)
    m, b = np.polyfit(x, y, 1)
    r = np.corrcoef(x, y)[0, 1]
    return m, b, r, r*r

def scatter_with_fit(df, x, y, xlabel, ylabel, title, fname):
    xv = df[x].values; yv = df[y].values
    m, b, r, r2 = linfit(xv, yv)
    xs = np.linspace(min(xv), max(xv), 200)
    plt.figure()
    plt.scatter(xv, yv, s=32, alpha=0.9, edgecolor="k", linewidth=0.3)
    plt.plot(xs, m*xs + b, linewidth=2.0, label=f"fit: y={m:.3f}x+{b:.3f}")
    plt.xlabel(xlabel); plt.ylabel(ylabel); plt.title(title)
    plt.grid(alpha=0.25); plt.legend(loc="best", frameon=True)
    plt.text(0.02, 0.98, f"$r={r:.2f}$, $R^2={r2:.2f}$", transform=plt.gca().transAxes,
             va="top", ha="left", bbox=dict(boxstyle="round,pad=0.3", fc="#a5d8ff", ec="none"))
    plt.savefig(fname, bbox_inches="tight"); plt.close()

def barh(values, labels, title, xlabel, fname):
    plt.figure()
    y_pos = np.arange(len(labels))
    plt.barh(y_pos, values, edgecolor="black", alpha=0.9)
    plt.yticks(y_pos, labels)
    plt.xlabel(xlabel); plt.title(title)
    plt.grid(axis='x', alpha=0.25)
    plt.savefig(fname, bbox_inches="tight"); plt.close()

# -------------------------- Load & Aggregate --------------------------

def load_and_aggregate(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    # Column names (be forgiving about variants)
    c_attack = ensure_col(df, ["Attack_ID", "attack", "Attack"])
    c_pcap   = ensure_col(df, ["PCAP_Size_MB", "pcap_mb"])
    c_zeek   = ensure_col(df, ["Zeek_Time_s", "zeek_sec"])
    c_det    = ensure_col(df, ["Detection_Time_s", "detect_sec"])
    c_inc    = ensure_col(df, ["Incident_Time_s", "incident_sec"], default="incident_fallback")
    c_total  = ensure_col(df, ["Total_Time_s", "total_sec"], default="total_fallback")

    # Alerts count column can vary
    c_alerts = ensure_col(df, ["Alerts_Generated", "alerts_count", "Alerts", "Alert_Count"])

    # Optional modbus_detailed size or reconstruct from throughput if available
    if "Modbus_Detailed_MB" in df.columns:
        c_modbus = "Modbus_Detailed_MB"
    elif "Detection_Throughput_MBps" in df.columns:
        # size ≈ time * throughput
        df["Modbus_Detailed_MB"] = df[c_det] * df["Detection_Throughput_MBps"]
        c_modbus = "Modbus_Detailed_MB"
    else:
        # fallback: use pcap size as a proxy
        df["Modbus_Detailed_MB"] = df[c_pcap]
        c_modbus = "Modbus_Detailed_MB"

    # ------------------ Normalize attack labels (CRITICAL) ------------------
    # Merge attack_13_main -> Attack 13 (and any 'A13_main' style)
    df["attack_norm"] = df[c_attack].apply(normalize_attack_id)

    # Keep only the columns we need with consistent names
    work = df[["attack_norm", c_pcap, c_modbus, c_alerts, c_zeek, c_det, c_inc, c_total]].copy()
    work.columns = ["attack", "pcap_mb", "modbus_detailed_mb", "alerts_count",
                    "zeek_sec", "detect_sec", "incident_sec", "total_sec"]

    # Aggregate by attack (median is robust)
    agg = work.groupby("attack", as_index=False).median(numeric_only=True)

    # Sort by numeric attack index
    def attack_num(a):
        m = re.search(r"(\d+)", a)
        return int(m.group(1)) if m else 0
    agg = agg.sort_values(by="attack", key=lambda s: s.map(attack_num)).reset_index(drop=True)

    return agg

# ------------------------------ Main ---------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Path to evaluation.csv")
    ap.add_argument("--outdir", default="figs", help="Output directory for figures")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    agg = load_and_aggregate(args.csv)

    # --- Alerts-per-Attack (one bar per attack; 13_main merged) ---
    plt.figure(figsize=(7.5, 4.2))
    plt.bar(agg["attack"], agg["alerts_count"], edgecolor="black", alpha=0.9)
    plt.title("Alerts per attack (median)")
    plt.ylabel("Alerts (median)")
    plt.xlabel("Attack")
    plt.xticks(rotation=60, ha="right")
    plt.grid(axis="y", alpha=0.25)
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, "alerts_per_attack.png"), bbox_inches="tight")
    plt.close()

    # --- Scatter plots (relationships) ---
    scatter_with_fit(agg, "pcap_mb", "zeek_sec",
                     "PCAP size (MB)", "Zeek parse time (s)",
                     "Zeek parse time vs PCAP size",
                     os.path.join(args.outdir, "scatter_zeek_vs_pcap.png"))

    scatter_with_fit(agg, "modbus_detailed_mb", "detect_sec",
                     "modbus_detailed.log size (MB)", "Detect time (s)",
                     "Detect time vs Modbus detailed size",
                     os.path.join(args.outdir, "scatter_detect_vs_modbus.png"))

    scatter_with_fit(agg, "alerts_count", "incident_sec",
                     "Alert count (per attack)", "Incident build time (s)",
                     "Incident time vs Alert count",
                     os.path.join(args.outdir, "scatter_incident_vs_alerts.png"))

    scatter_with_fit(agg, "pcap_mb", "total_sec",
                     "PCAP size (MB)", "Total pipeline time (s)",
                     "Total time vs PCAP size",
                     os.path.join(args.outdir, "scatter_total_vs_pcap.png"))

    scatter_with_fit(agg, "modbus_detailed_mb", "total_sec",
                     "modbus_detailed.log size (MB)", "Total pipeline time (s)",
                     "Total time vs Modbus detailed size",
                     os.path.join(args.outdir, "scatter_total_vs_modbus.png"))

    # --- Multiple Regression: total_sec ~ pcap_mb + modbus_detailed_mb + alerts_count ---
    X_raw = agg[["pcap_mb", "modbus_detailed_mb", "alerts_count"]].values
    y = agg["total_sec"].values
    X = np.column_stack([np.ones(len(agg)), X_raw])
    beta, _, _, r2 = multiple_regression(X, y)

    # Standardized (z-scores) for relative importance
    Z = np.column_stack([
        standardize(agg["pcap_mb"].values),
        standardize(agg["modbus_detailed_mb"].values),
        standardize(agg["alerts_count"].values),
    ])
    beta_std, _, _, r2_std = multiple_regression(np.column_stack([np.ones(len(agg)), Z]),
                                                 standardize(agg["total_sec"].values))

    coef_df = pd.DataFrame({
        "term": ["Intercept", "pcap_mb", "modbus_detailed_mb", "alerts_count"],
        "coef": [f"{v:.4f}" for v in beta]
    })
    coef_df_std = pd.DataFrame({
        "term": ["Intercept", "pcap_mb", "modbus_detailed_mb", "alerts_count"],
        "std_coef": [f"{v:.3f}" for v in beta_std]
    })

    make_png_table(
        coef_df,
        f"Multiple regression: total_sec ~ pcap_mb + modbus_detailed_mb + alerts_count (R²={r2:.3f})",
        os.path.join(args.outdir, "regression_coefficients.png")
    )
    make_png_table(
        coef_df_std,
        f"Standardized betas (z-scores) (R²={r2_std:.3f})",
        os.path.join(args.outdir, "regression_std_coefficients.png")
    )

    # Bar of standardized betas (relative contribution)
    barh(
        values=[float(coef_df_std.loc[coef_df_std.term=="pcap_mb", "std_coef"].item()),
                float(coef_df_std.loc[coef_df_std.term=="modbus_detailed_mb", "std_coef"].item()),
                float(coef_df_std.loc[coef_df_std.term=="alerts_count", "std_coef"].item())],
        labels=["pcap_mb", "modbus_detailed_mb", "alerts_count"],
        title="Relative contribution to total pipeline time (standardized betas)",
        xlabel="Standardized coefficient (β)",
        fname=os.path.join(args.outdir, "regression_std_bars.png")
    )

    # --- Key Correlations table ---
    def corr(a, b): return float(np.corrcoef(agg[a], agg[b])[0, 1])
    cdf = pd.DataFrame([
        {"pair": "Zeek~PCAP",         "Pearson r": f"{corr('zeek_sec','pcap_mb'):.3f}"},
        {"pair": "Detect~ModbusDet",  "Pearson r": f"{corr('detect_sec','modbus_detailed_mb'):.3f}"},
        {"pair": "Incident~Alerts",   "Pearson r": f"{corr('incident_sec','alerts_count'):.3f}"},
        {"pair": "Total~PCAP",        "Pearson r": f"{corr('total_sec','pcap_mb'):.3f}"},
        {"pair": "Total~ModbusDet",   "Pearson r": f"{corr('total_sec','modbus_detailed_mb'):.3f}"},
        {"pair": "Total~Alerts",      "Pearson r": f"{corr('total_sec','alerts_count'):.3f}"},
    ])
    make_png_table(
        cdf,
        "Key correlations (Pearson r)",
        os.path.join(args.outdir, "correlation_table.png")
    )

    # Save the aggregated medians (reproducibility)
    agg.to_csv(os.path.join(args.outdir, "eval_aggregate_medians.csv"), index=False)

if __name__ == "__main__":
    main()
