
import re
from pathlib import Path

import numpy as np

try:
    import pandas as pd
except Exception:
    raise SystemExit("pandas is required. Install: pip install pandas matplotlib numpy")

import matplotlib
matplotlib.use("Agg")  # headless / CI safe
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# Professional defaults
plt.rcParams["figure.figsize"] = (12, 5)
plt.rcParams["figure.dpi"] = 120

# ----------------------------
# Paths
# ----------------------------
HERE = Path(__file__).resolve().parent          # graphs folder
OUTDIR = HERE                                   # all PNGs + dashboard go here
BASE = HERE.parent                              # output folder where CSVs live

TS_PATH = BASE / "timeseries_per_minute.csv"
ENTRIES_PATH = BASE / "entries.csv"

OUTDIR.mkdir(parents=True, exist_ok=True)

# ----------------------------
# Helpers
# ----------------------------
def _save(name: str):
    p = OUTDIR / name
    plt.tight_layout()
    plt.savefig(p, dpi=180)
    plt.close()


def _format_time_axis(ax=None):
    """Reduce tick overlap for time series plots."""
    if ax is None:
        ax = plt.gca()
    ax.xaxis.set_major_locator(mdates.AutoDateLocator())
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %H:%M"))
    for label in ax.get_xticklabels():
        label.set_rotation(45)
        label.set_ha("right")

def _break_large_gaps(x, y, max_gap_minutes=10):
    """Insert NaNs to prevent misleading straight lines across big time gaps."""
    if len(x) <= 1:
        return x, y
    x = pd.to_datetime(pd.Series(x)).reset_index(drop=True)
    y = pd.Series(y).reset_index(drop=True)
    out_x = [x.iloc[0]]
    out_y = [y.iloc[0]]
    for i in range(1, len(x)):
        gap = (x.iloc[i] - x.iloc[i-1]).total_seconds() / 60.0
        if gap > max_gap_minutes:
            out_x.append(x.iloc[i-1] + pd.Timedelta(minutes=1))
            out_y.append(np.nan)
        out_x.append(x.iloc[i])
        out_y.append(y.iloc[i])
    return pd.Series(out_x), pd.Series(out_y)

def _safe_title(s: str, max_len: int = 60) -> str:
    s = str(s)
    s = re.sub(r"\s+", " ", s).strip()
    return (s[:max_len] + "…") if len(s) > max_len else s

def _minute_floor(ts: pd.Timestamp) -> pd.Timestamp:
    # keep timezone
    return ts.floor("min")

def _drop_final_partial_minute(df_ts: pd.DataFrame, df_entries: pd.DataFrame) -> pd.DataFrame:
    """
    Your last minute bucket can be incomplete if the log file ends mid-minute.
    This causes an artificial "drop" at the end of time-series plots.
    Fix: if the last observed event is far from the end of its minute, drop that final bucket.
    """
    if df_ts.empty:
        return df_ts
    if df_entries is None or df_entries.empty:
        return df_ts  # can't confirm partial window safely

    max_t = df_entries["t"].max()
    last_bucket = df_ts["t"].iloc[-1]
    # ensure comparable tz
    if getattr(max_t, "tzinfo", None) is None and getattr(last_bucket, "tzinfo", None) is not None:
        max_t = max_t.tz_localize(last_bucket.tzinfo)

    # seconds into the minute covered by the log
    covered = (max_t - last_bucket).total_seconds()
    # If file ends early in the last minute, drop the bucket for cleaner visuals.
    # 50s is a good practical cutoff (keeps buckets that are almost complete).
    if covered < 50:
        return df_ts.iloc[:-1].copy()
    return df_ts

def read_timeseries():
    df = pd.read_csv(TS_PATH)
    df["t"] = pd.to_datetime(df["minute_iso"], errors="coerce", utc=True)
    df = df.dropna(subset=["t"]).sort_values("t")
    for c in [c for c in df.columns if c not in ("minute_iso", "t")]:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    return df

def read_entries():
    if not ENTRIES_PATH.exists():
        return pd.DataFrame(columns=["timestamp_iso", "level", "source", "message", "t"])
    df = pd.read_csv(ENTRIES_PATH)
    df["t"] = pd.to_datetime(df["timestamp_iso"], errors="coerce", utc=True)
    df = df.dropna(subset=["t"]).sort_values("t")
    for c in ["level", "source", "message"]:
        if c not in df.columns:
            df[c] = ""
        df[c] = df[c].astype(str)
    return df

# ----------------------------
# Existing 9 graphs
# ----------------------------
def plot_01_log_volume(df_ts):
    plt.figure()
    x, y = _break_large_gaps(df_ts["t"], df_ts.get("total", 0))
    plt.plot(x, y, label="total")
    plt.xlabel("Time")
    plt.ylabel("Log count / minute")
    plt.title("Log Volume Over Time")
    plt.legend()
    _format_time_axis()
    _save("01_log_volume_over_time.png")

def plot_02_error_rate(df_ts):
    plt.figure()
    x, y = _break_large_gaps(df_ts["t"], df_ts.get("error", 0))
    plt.plot(x, y, label="ERROR")
    plt.xlabel("Time")
    plt.ylabel("ERROR count / minute")
    plt.title("Error Rate Over Time")
    plt.legend()
    _format_time_axis()
    _save("02_error_rate_over_time.png")

def plot_03_level_stacked_area(df_ts):
    levels = [c for c in ["trace", "debug", "info", "warn", "error", "critical", "unknown"] if c in df_ts.columns]
    if not levels:
        return
    x = df_ts["t"]
    ys = [df_ts[c].to_numpy(dtype=float) for c in levels]
    plt.figure()
    plt.stackplot(x, ys, labels=[c.upper() for c in levels])
    plt.xlabel("Time")
    plt.ylabel("Count / minute")
    plt.title("Log Level Distribution Over Time (Stacked)")
    plt.legend(loc="upper left", ncol=2)
    _format_time_axis()
    _save("03_log_level_distribution_over_time_stacked.png")


def plot_04_moving_average(df_ts, window=10):
    total = df_ts.get("total", pd.Series([0] * len(df_ts)))
    ma = pd.Series(total).rolling(window=window, min_periods=1).mean()
    plt.figure()
    x, y = _break_large_gaps(df_ts["t"], total)
    plt.plot(x, y, label="total", alpha=0.35)
    x2, y2 = _break_large_gaps(df_ts["t"], ma)
    plt.plot(x2, y2, label=f"moving avg (w={window})")
    plt.xlabel("Time")
    plt.ylabel("Log count / minute")
    plt.title("Moving Average Trend (Log Volume)")
    plt.legend()
    _format_time_axis()
    _save("04_moving_average_trend.png")

def plot_05_zscore(df_ts, threshold=3.0):
    total = pd.Series(df_ts.get("total", 0)).astype(float)
    mu = float(total.mean()) if len(total) else 0.0
    sigma = float(total.std(ddof=0)) if len(total) else 0.0
    if sigma == 0:
        z = total * 0.0
    else:
        z = (total - mu) / sigma

    plt.figure()
    x, y = _break_large_gaps(df_ts["t"], z)
    plt.plot(x, y, label="z-score")
    plt.axhline(threshold, linestyle="--", label=f"+{threshold}")
    plt.axhline(-threshold, linestyle="--", label=f"-{threshold}")
    breaches = df_ts.loc[np.abs(z) >= threshold]
    if len(breaches):
        plt.scatter(breaches["t"], z.loc[breaches.index], s=18, label="breach")
    plt.xlabel("Time")
    plt.ylabel("Z-score")
    plt.title("Z-Score Over Time (Log Volume)")
    plt.legend()
    _format_time_axis()
    _save("05_zscore_over_time.png")

def plot_06_level_distribution(df_entries, df_ts):
    counts = None
    if len(df_entries):
        counts = df_entries["level"].str.upper().value_counts()
    else:
        cols = [c for c in ["trace", "debug", "info", "warn", "error", "critical", "unknown"] if c in df_ts.columns]
        if cols:
            counts = pd.Series({c.upper(): float(df_ts[c].sum()) for c in cols})
    if counts is None or len(counts) == 0:
        return

    plt.figure()
    counts = counts.sort_values(ascending=False)
    plt.bar(counts.index.tolist(), counts.values.tolist())
    plt.xlabel("Level")
    plt.ylabel("Count")
    plt.title("Log Level Distribution")
    _save("06_log_level_distribution_bar.png")

def plot_07_service_activity(df_entries):
    if not len(df_entries):
        return
    counts = df_entries["source"].replace({"nan": "unknown"}).fillna("unknown").value_counts().head(15)
    plt.figure()
    plt.bar(counts.index.tolist(), counts.values.tolist())
    plt.xlabel("Service / Source (top 15)")
    plt.ylabel("Count")
    plt.title("Service Activity Distribution")
    plt.xticks(rotation=30, ha="right")
    _save("07_service_activity_distribution.png")

def plot_08_top_error_messages(df_entries, topn=10):
    if not len(df_entries):
        return
    lv = df_entries["level"].str.upper()
    err = df_entries[lv.isin(["ERROR", "CRITICAL"])]
    if not len(err):
        return
    msg = err["message"].astype(str)
    msg = msg.str.replace(r"\b\d+\b", "0", regex=True)
    msg = msg.str.replace(r"\s+", " ", regex=True).str.strip()
    counts = msg.value_counts().head(topn)
    if not len(counts):
        return
    labels = [_safe_title(s, 70) for s in counts.index.tolist()]
    plt.figure()
    y = np.arange(len(counts))
    plt.barh(y, counts.values[::-1])
    plt.yticks(y, labels[::-1])
    plt.xlabel("Count")
    plt.title(f"Top {topn} Error Messages")
    _save("08_top_error_messages.png")

def plot_09_ip_frequency(df_entries, topn=15):
    if not len(df_entries):
        return
    blob = (df_entries["message"].astype(str) + " " + df_entries["source"].astype(str))
    ips = blob.str.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    flat = [ip for sub in ips.tolist() for ip in sub]
    if not flat:
        return
    counts = pd.Series(flat).value_counts().head(topn)
    plt.figure()
    plt.bar(counts.index.tolist(), counts.values.tolist())
    plt.xlabel("IP (top)")
    plt.ylabel("Count")
    plt.title("IP Address Frequency")
    plt.xticks(rotation=30, ha="right")
    _save("09_ip_address_frequency.png")

# ----------------------------
# Professional upgrades
# ----------------------------
def plot_10_heatmap_time_vs_log_level(df_ts):
    levels = [c for c in ["trace", "debug", "info", "warn", "error", "critical", "unknown"] if c in df_ts.columns]
    if not levels or len(df_ts) < 2:
        return

    mat = np.vstack([df_ts[c].to_numpy(dtype=float) for c in levels])  # (L, T)

    plt.figure()
    plt.imshow(mat, aspect="auto", interpolation="nearest")
    plt.yticks(np.arange(len(levels)), [c.upper() for c in levels])
    # sparse x ticks
    xt = np.linspace(0, len(df_ts) - 1, num=min(10, len(df_ts)), dtype=int)
    plt.xticks(xt, [df_ts["t"].iloc[i].strftime("%m-%d %H:%M") for i in xt], rotation=30, ha="right")
    plt.xlabel("Time")
    plt.title("Heatmap: Time vs Log Level")
    plt.colorbar(label="Count / minute")
    _save("10_heatmap_time_vs_log_level.png")

def plot_11_correlation_matrix_services(df_entries, top_services=20):
    if df_entries.empty:
        return

    # minute bucket per service
    df = df_entries.copy()
    df["minute"] = df["t"].dt.floor("min")
    top = df["source"].value_counts().head(top_services).index.tolist()
    df = df[df["source"].isin(top)]

    pivot = df.pivot_table(index="minute", columns="source", values="message", aggfunc="count").fillna(0.0)

    if pivot.shape[1] < 2:
        return

    corr = pivot.corr()

    plt.figure()
    plt.imshow(corr.to_numpy(), aspect="auto", interpolation="nearest", vmin=-1, vmax=1)
    plt.xticks(np.arange(len(corr.columns)), corr.columns.tolist(), rotation=45, ha="right")
    plt.yticks(np.arange(len(corr.index)), corr.index.tolist())
    plt.title("Service Correlation Matrix (per-minute activity)")
    plt.colorbar(label="Correlation")
    _save("11_service_correlation_matrix.png")

def plot_12_isolation_forest_scores(df_ts, df_entries):
    """
    Isolation Forest anomaly score per minute (professional ML plot).
    If scikit-learn is not installed, we skip and print a message.
    """
    try:
        from sklearn.ensemble import IsolationForest
    except Exception:
        print("Skipping Isolation Forest: scikit-learn not installed (pip install scikit-learn).")
        return

    df = df_ts.copy()
    # add a couple of helpful features if entries exist
    if df_entries is not None and not df_entries.empty:
        e = df_entries.copy()
        e["minute"] = e["t"].dt.floor("min")
        # unique sources + unique IPs per minute
        uniq_src = e.groupby("minute")["source"].nunique()
        blob = (e["message"].astype(str) + " " + e["source"].astype(str))
        ips = blob.str.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        e["ip"] = ips.apply(lambda xs: xs[0] if xs else np.nan)
        uniq_ip = e.groupby("minute")["ip"].nunique()
        df = df.set_index("t")
        df["unique_sources"] = uniq_src
        df["unique_ips"] = uniq_ip
        df = df.fillna(0.0).reset_index()

    # feature columns
    feats = []
    for c in ["total", "error", "warn", "critical", "anomalies", "malformed", "unique_sources", "unique_ips"]:
        if c in df.columns:
            feats.append(c)
    if len(feats) < 2:
        feats = ["total"] if "total" in df.columns else feats
    if not feats:
        return

    X = df[feats].to_numpy(dtype=float)

    # Fit model
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)

    # decision_function: higher = more normal. We'll invert so higher = more anomalous.
    normality = model.decision_function(X)
    score = -normality

    plt.figure()
    plt.plot(df["t"], score, label="anomaly score")
    # mark top 1% as red dots
    k = max(1, int(0.01 * len(score)))
    idx = np.argsort(score)[-k:]
    plt.scatter(df["t"].iloc[idx], np.array(score)[idx], s=18, label="top 1% anomalies")
    plt.xlabel("Time")
    plt.ylabel("Isolation Forest score (higher = more anomalous)")
    plt.title("Isolation Forest Anomaly Score Over Time")
    plt.legend()
    _save("12_isolation_forest_anomaly_score.png")

def write_html_dashboard():
    # Collect images (sorted)
    imgs = sorted([p.name for p in OUTDIR.glob("*.png")])
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Log Analysis Dashboard</title>
<style>
body{{font-family:Arial, sans-serif; margin:24px; background:#fafafa; color:#111;}}
h1{{margin:0 0 8px 0;}}
.small{{color:#555; margin-bottom:18px;}}
.grid{{display:grid; grid-template-columns:repeat(auto-fit,minmax(360px,1fr)); gap:16px;}}
.card{{background:#fff; border:1px solid #e6e6e6; border-radius:12px; padding:12px; box-shadow:0 1px 2px rgba(0,0,0,.04);}}
.card img{{width:100%; height:auto; border-radius:8px;}}
.caption{{margin-top:8px; font-size:14px; color:#333;}}
</style>
</head>
<body>
<h1>Log Analysis Dashboard</h1>
<div class="small">Folder: {OUTDIR.name} • Generated by plot_all_graphs.py</div>
<div class="grid">
{''.join([f'<div class="card"><img src="{name}" alt="{name}"/><div class="caption">{name}</div></div>' for name in imgs])}
</div>
</body>
</html>
"""
    (OUTDIR / "index.html").write_text(html, encoding="utf-8")

def main():
    if not TS_PATH.exists():
        raise SystemExit(f"Missing {TS_PATH}. Run the C++ tool with --graphs first.")

    df_ts = read_timeseries()
    df_entries = read_entries()

    # Fix the "last bucket drop" visually
    df_ts = _drop_final_partial_minute(df_ts, df_entries)

    # Core 9
    plot_01_log_volume(df_ts)
    plot_02_error_rate(df_ts)
    plot_03_level_stacked_area(df_ts)
    plot_04_moving_average(df_ts)
    plot_05_zscore(df_ts)
    plot_06_level_distribution(df_entries, df_ts)
    plot_07_service_activity(df_entries)
    plot_08_top_error_messages(df_entries)
    plot_09_ip_frequency(df_entries)

    # Upgrades
    plot_10_heatmap_time_vs_log_level(df_ts)
    plot_11_correlation_matrix_services(df_entries)
    plot_12_isolation_forest_scores(df_ts, df_entries)

    # Dashboard
    write_html_dashboard()

    print(f"Done. Wrote PNGs + index.html to: {OUTDIR}")

if __name__ == "__main__":
    main()
