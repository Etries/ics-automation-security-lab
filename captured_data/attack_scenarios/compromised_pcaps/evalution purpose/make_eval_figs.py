#!/usr/bin/env python3
import os, numpy as np, pandas as pd, matplotlib.pyplot as plt

plt.rcParams.update({"figure.dpi": 140, "font.size": 10, "axes.titlesize": 12, "axes.labelsize": 11})

def load_and_aggregate(csv_path):
    df = pd.read_csv(csv_path)
    # Required columns in your evaluation.csv:
    # Attack_ID, PCAP_Size_MB, Alerts_Generated, Zeek_Time_s, Detection_Time_s, Incident_Time_s, Total_Time_s
    # Optional: Modbus_Detailed_MB; otherwise we reconstruct from Detection_Time_s * Detection_Throughput_MBps
    if "Modbus_Detailed_MB" not in df.columns:
        if "Detection_Throughput_MBps" in df.columns:
            df["Modbus_Detailed_MB"] = df["Detection_Time_s"] * df["Detection_Throughput_MBps"]
        else:
            df["Modbus_Detailed_MB"] = df["PCAP_Size_MB"]
    work = df[["Attack_ID","PCAP_Size_MB","Modbus_Detailed_MB","Alerts_Generated",
               "Zeek_Time_s","Detection_Time_s","Incident_Time_s","Total_Time_s"]].copy()
    work.columns = ["attack","pcap_mb","modbus_detailed_mb","alerts_count",
                    "zeek_sec","detect_sec","incident_sec","total_sec"]
    agg = work.groupby("attack").median(numeric_only=True).reset_index()
    return agg

PALETTE = {"fill":"#a5d8ff"}

def linfit(x, y):
    x = np.asarray(x, float); y = np.asarray(y, float)
    m, b = np.polyfit(x, y, 1)
    r = np.corrcoef(x, y)[0,1]
    return m, b, r, r*r

def scatter_with_fit(df, x, y, xlabel, ylabel, title, fname, c1, c2):
    xv = df[x].values; yv = df[y].values
    m, b, r, r2 = linfit(xv, yv)
    xs = np.linspace(min(xv), max(xv), 200)
    plt.figure()
    plt.scatter(xv, yv, s=32, alpha=0.9, edgecolor="k", linewidth=0.3, c=c1)
    plt.plot(xs, m*xs + b, color=c2, linewidth=2.0, label=f"fit: y={m:.3f}x+{b:.3f}")
    plt.xlabel(xlabel); plt.ylabel(ylabel); plt.title(title)
    plt.grid(alpha=0.25); plt.legend(loc="best", frameon=True)
    plt.text(0.02, 0.98, f"$r={r:.2f}$, $R^2={r2:.2f}$", transform=plt.gca().transAxes,
             va="top", ha="left", bbox=dict(boxstyle="round,pad=0.3", fc=PALETTE["fill"], ec="none"))
    plt.savefig(fname, bbox_inches="tight"); plt.close()

def standardize(a):
    a = np.asarray(a, float)
    return (a - a.mean()) / (a.std(ddof=0) + 1e-12)

def multiple_regression(X, y):
    X = np.asarray(X, float); y = np.asarray(y, float)
    beta = np.linalg.inv(X.T @ X) @ (X.T @ y)
    yhat = X @ beta
    resid = y - yhat
    rss = float(np.sum(resid**2)); tss = float(np.sum((y - y.mean())**2))
    r2 = float(1 - rss/tss)
    return beta, yhat, resid, r2

def bar_coefficients(labels, values, title, ylabel, fname, color):
    import matplotlib.pyplot as plt
    plt.figure()
    y_pos = np.arange(len(labels))
    plt.barh(y_pos, values, color=color, edgecolor="k", alpha=0.9)
    plt.yticks(y_pos, labels)
    plt.xlabel(ylabel); plt.title(title)
    plt.grid(axis='x', alpha=0.25)
    plt.savefig(fname, bbox_inches="tight"); plt.close()

def make_png_table(df, title, fname):
    import matplotlib.pyplot as plt
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

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="evaluation.csv")
    ap.add_argument("--outdir", default="figs")
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)
    agg = load_and_aggregate(args.csv)
    # Figures
    scatter_with_fit(agg, "pcap_mb", "zeek_sec", "PCAP size (MB)", "Zeek parse time (s)",
                     "Zeek parse time vs PCAP size", os.path.join(args.outdir,"scatter_zeek_vs_pcap.png"),
                     "#2a9d8f", "#264653")
    scatter_with_fit(agg, "modbus_detailed_mb", "detect_sec", "modbus_detailed.log size (MB)", "Detect time (s)",
                     "Detect time vs Modbus detailed size", os.path.join(args.outdir,"scatter_detect_vs_modbus.png"),
                     "#e76f51", "#457b9d")
    scatter_with_fit(agg, "alerts_count", "incident_sec", "Alert count (per attack)", "Incident build time (s)",
                     "Incident time vs Alert count", os.path.join(args.outdir,"scatter_incident_vs_alerts.png"),
                     "#e63946", "#1d3557")
    scatter_with_fit(agg, "pcap_mb", "total_sec", "PCAP size (MB)", "Total pipeline time (s)",
                     "Total time vs PCAP size", os.path.join(args.outdir,"scatter_total_vs_pcap.png"),
                     "#5a189a", "#00b4d8")
    scatter_with_fit(agg, "modbus_detailed_mb", "total_sec", "modbus_detailed.log size (MB)", "Total pipeline time (s)",
                     "Total time vs Modbus detailed size", os.path.join(args.outdir,"scatter_total_vs_modbus.png"),
                     "#3a0ca3", "#f8961e")
    # Regression
    X_raw = agg[["pcap_mb","modbus_detailed_mb","alerts_count"]].values
    y = agg["total_sec"].values
    X = np.column_stack([np.ones(len(agg)), X_raw])
    beta, _, _, r2 = multiple_regression(X, y)
    Z = np.column_stack([standardize(agg["pcap_mb"]), standardize(agg["modbus_detailed_mb"]), standardize(agg["alerts_count"])])
    beta_std, _, _, r2_std = multiple_regression(np.column_stack([np.ones(len(agg)), Z]), standardize(agg["total_sec"]))
    coef_df = pd.DataFrame({"term":["Intercept","pcap_mb","modbus_detailed_mb","alerts_count"], "coef": np.round(beta,4)})
    coef_df_std = pd.DataFrame({"term":["Intercept","pcap_mb","modbus_detailed_mb","alerts_count"], "std_coef": np.round(beta_std,3)})
    make_png_table(coef_df.assign(coef=coef_df["coef"].map(lambda v: f"{v:.4f}")), 
                   f"Multiple regression: total_sec ~ pcap_mb + modbus_detailed_mb + alerts_count (R²={r2:.3f})",
                   os.path.join(args.outdir,"regression_coefficients.png"))
    make_png_table(coef_df_std.assign(std_coef=coef_df_std["std_coef"].map(lambda v: f"{v:.3f}")),
                   f"Standardized betas (z-scores) (R²={r2_std:.3f})",
                   os.path.join(args.outdir,"regression_std_coefficients.png"))
    bar_coefficients(["pcap_mb","modbus_detailed_mb","alerts_count"], list(coef_df_std["std_coef"].values[1:]),
                     "Relative contribution to total pipeline time (standardized betas)",
                     "Standardized coefficient (β)",
                     os.path.join(args.outdir,"regression_std_bars.png"), "#e8590c")
    # Correlations
    def corr(a,b): return float(np.corrcoef(agg[a], agg[b])[0,1])
    cdf = pd.DataFrame([
        {"pair":"Zeek~PCAP","Pearson r": f"{corr('zeek_sec','pcap_mb'):.3f}"},
        {"pair":"Detect~ModbusDet","Pearson r": f"{corr('detect_sec','modbus_detailed_mb'):.3f}"},
        {"pair":"Incident~Alerts","Pearson r": f"{corr('incident_sec','alerts_count'):.3f}"},
        {"pair":"Total~PCAP","Pearson r": f"{corr('total_sec','pcap_mb'):.3f}"},
        {"pair":"Total~ModbusDet","Pearson r": f"{corr('total_sec','modbus_detailed_mb'):.3f}"},
        {"pair":"Total~Alerts","Pearson r": f"{corr('total_sec','alerts_count'):.3f}"}
    ])
    make_png_table(cdf, "Key correlations (Pearson r)", os.path.join(args.outdir,"correlation_table.png"))
    # Save medians for reproducibility
    agg.to_csv(os.path.join(args.outdir, "eval_aggregate_medians.csv"), index=False)

if __name__ == "__main__":
    main()
