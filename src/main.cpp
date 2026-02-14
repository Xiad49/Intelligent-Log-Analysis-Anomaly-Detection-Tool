#include <iostream>
#include <fstream>
#include <string>
#include <optional>
#include <chrono>
#include <filesystem>
#include <limits>
#include <map>
#include <iomanip>
#include <sstream>
#include <ctime>

// Core models
#include "core/LogEntry.hpp"
#include "core/Report.hpp"
#include "core/Anomaly.hpp"

// Input
#include "input/LogParser.hpp"

// Utils
#include "utils/Logger.hpp"
#include "utils/ConfigLoader.hpp"

// Analysis
#include "analysis/FrequencyAnalyzer.hpp"
#include "analysis/TimeWindowAnalyzer.hpp"
#include "analysis/PatternAnalyzer.hpp"

// Anomaly detection
#include "anomaly/RuleBasedDetector.hpp"
#include "anomaly/SpikeDetector.hpp"
#include "anomaly/StatisticalDetector.hpp"
#include "anomaly/BurstPatternDetector.hpp"
#include "anomaly/IpFrequencyDetector.hpp"

// Reporting
#include "report/ReportGenerator.hpp"
#include "report/ConsoleReporter.hpp"
#include "report/JsonReporter.hpp"
#include "report/CsvReporter.hpp"

// -------------------------
// CLI
// -------------------------
struct CliOptions
{
    std::string inputFile;
    std::string configFile = "config/default_config.json";
    std::string outputDir = ".";
    bool verbose = false;
    bool json = false;
    bool csv = false;
    bool graphs = false;
};

static CliOptions parseArgs(int argc, char *argv[])
{
    CliOptions opts;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--config" || arg == "-c")
        {
            if (++i < argc)
                opts.configFile = argv[i];
        }
        else if (arg == "--output" || arg == "-o")
        {
            if (++i < argc)
                opts.outputDir = argv[i];
        }
        else if (arg == "--verbose" || arg == "-v")
        {
            opts.verbose = true;
        }
        else if (arg == "--json")
        {
            opts.json = true;
        }
        else if (arg == "--csv")
        {
            opts.csv = true;
        }
        else if (arg == "--graphs")
        {
            opts.graphs = true;
        }
        else if (!arg.empty() && arg[0] != '-')
        {
            opts.inputFile = arg;
        }
    }

    return opts;
}

static void printUsage(const char *progName)
{
    std::cout
        << "Usage: " << progName << " [OPTIONS] input.log\n\n"
        << "OPTIONS:\n"
        << "  -c, --config FILE        Config file (default: config/default_config.json)\n"
        << "  -o, --output DIR         Output directory (default: .)\n"
        << "  -v, --verbose            Verbose logging\n"
        << "  --json                   Export JSON report\n"
        << "  --csv                    Export CSV report\n"
        << "  --graphs                 Export time-series CSV + Python plotting script\n\n";
}

int main(int argc, char *argv[])
{
    const auto opts = parseArgs(argc, argv);

    if (opts.inputFile.empty())
    {
        std::cerr << "Error: input file required.\n\n";
        printUsage(argv[0]);
        return 1;
    }

    // Logger
    auto &logger = LogTool::Utils::getLogger();
    if (opts.verbose)
        logger.setLevel(LogTool::Utils::LogLevel::DEBUG);

    logger.info("Starting Log Analysis Tool");
    logger.info("Input: " + opts.inputFile);
    logger.info("Output dir: " + opts.outputDir);

    // Output directory
    try
    {
        std::filesystem::create_directories(opts.outputDir);
    }
    catch (...)
    { /* ignore */
    }

    // ConfigLoader in your project currently default-constructs.
    // (You can extend it later with loadFromFile(path).)
    LogTool::Utils::ConfigLoader config;

    // Pipeline components
    LogTool::Input::LogParser parser;

    LogTool::Analysis::FrequencyAnalyzer freq;
    LogTool::Analysis::TimeWindowAnalyzer timeWindow;
    LogTool::Analysis::PatternAnalyzer pattern;

    LogTool::Anomaly::RuleBasedDetector ruleDetector;
    LogTool::Anomaly::SpikeDetector spikeDetector;
    LogTool::Anomaly::StatisticalDetector statDetector;
    LogTool::Anomaly::BurstPatternDetector burstDetector;
    LogTool::Anomaly::IpFrequencyDetector ipDetector;

    core::Report report;
    report.setProcessedFile(opts.inputFile);

    // Process file
    std::ifstream file(opts.inputFile);
    if (!file.is_open())
    {
        logger.error("Cannot open input file: " + opts.inputFile);
        return 1;
    }

    logger.info("Batch processing mode");
    const auto wallStart = std::chrono::steady_clock::now();

    std::string line;
    std::uint64_t parsedCount = 0;
    std::uint64_t malformedCount = 0;
    std::uint64_t emittedCount = 0;

    struct MinuteStats
    {
        std::uint64_t total = 0, trace = 0, debug = 0, info = 0, warn = 0, error = 0, critical = 0, unknown = 0, anomalies = 0, malformed = 0;
    };
    std::map<std::time_t, MinuteStats> ts;
    auto bucketOf = [](const core::LogEntry::TimePoint &tp) -> std::time_t
    {
        const std::time_t t = core::LogEntry::Clock::to_time_t(tp);
        return (t / 60) * 60;
    };
    std::time_t lastBucket = 0;

    bool haveTimeRange = false;
    core::LogEntry::TimePoint minTs{};
    core::LogEntry::TimePoint maxTs{};

    while (std::getline(file, line))
    {
        if (line.empty())
            continue;

        auto pr = parser.parseLineDetailed(line);
        if (!pr.entry.has_value())
        {
            ++malformedCount;
            // Treat malformed lines as anomalies (test: "Malformed log handling")
            const auto nowTp = core::Report::Clock::now();
            const std::time_t b = (lastBucket != 0) ? lastBucket : bucketOf(nowTp);
            ts[b].malformed++;

            core::Anomaly a(core::AnomalyType::Other,
                            core::AnomalySeverity::Low,
                            nowTp,
                            nowTp,
                            1.0,
                            "Malformed log line: " + (pr.error.empty() ? std::string("parse failure") : pr.error),
                            std::optional<std::string>("parser"),
                            {});
            report.addAnomaly(std::move(a));
            ++emittedCount;
            continue;
        }

        const core::LogEntry &entry = *pr.entry;
        ++parsedCount;

        // Time-series bucket (for graphs)
        const std::time_t b = bucketOf(entry.timestamp());
        lastBucket = b;
        auto &m = ts[b];
        ++m.total;
        switch (entry.level())
        {
        case core::LogLevel::Trace:
            ++m.trace;
            break;
        case core::LogLevel::Debug:
            ++m.debug;
            break;
        case core::LogLevel::Info:
            ++m.info;
            break;
        case core::LogLevel::Warn:
            ++m.warn;
            break;
        case core::LogLevel::Error:
            ++m.error;
            break;
        case core::LogLevel::Critical:
            ++m.critical;
            break;
        default:
            ++m.unknown;
            break;
        }

        // Track analysis time range based on parsed timestamps
        if (!haveTimeRange)
        {
            minTs = entry.timestamp();
            maxTs = entry.timestamp();
            haveTimeRange = true;
        }
        else
        {
            if (entry.timestamp() < minTs)
                minTs = entry.timestamp();
            if (entry.timestamp() > maxTs)
                maxTs = entry.timestamp();
        }

        // Update stats in Report
        report.incrementLevelCount(entry.level(), /*isAnomaly=*/false);
        report.updateSourceStats(entry.source().value_or("unknown"), entry.level());

        // Feed analyzers (kept for future/report enrichment)
        freq.addEntry(entry);
        timeWindow.addEntry(entry);
        pattern.addEntry(entry);

        // -------------------------
        // Real-time anomaly detectors
        // -------------------------

        // Rule-based anomalies
        auto matches = ruleDetector.checkEntry(entry);
        auto anomalies = ruleDetector.matchesToAnomalies(matches, entry);

        for (auto &a : anomalies)
        {
            report.addAnomaly(std::move(a));
            report.incrementLevelCount(entry.level(), /*isAnomaly=*/true);
            ++ts[b].anomalies;
            ++emittedCount;
        }

        // Spike detector (sliding window)
        for (const auto &s : spikeDetector.processEntry(entry))
        {
            core::Anomaly a(
                core::AnomalyType::FrequencySpike,
                s.severity >= 0.9 ? core::AnomalySeverity::Critical : (s.severity >= 0.6 ? core::AnomalySeverity::High : core::AnomalySeverity::Medium),
                s.stats.windowStart,
                s.stats.windowEnd,
                s.stats.spikeRatio,
                s.description,
                s.stats.source.empty() ? std::optional<std::string>{} : std::optional<std::string>(s.stats.source),
                s.sampleEvents);
            report.addAnomaly(std::move(a));
            ++ts[b].anomalies;
            ++emittedCount;
        }

        // Statistical detector (Z-score)
        for (const auto &st : statDetector.processEntry(entry))
        {
            core::Anomaly a(
                core::AnomalyType::StatisticalOutlier,
                st.severity >= 0.9 ? core::AnomalySeverity::High : (st.severity >= 0.6 ? core::AnomalySeverity::Medium : core::AnomalySeverity::Low),
                entry.timestamp(),
                entry.timestamp(),
                st.zscore,
                st.description,
                entry.source(),
                {entry});
            report.addAnomaly(std::move(a));
            ++ts[b].anomalies;
            ++emittedCount;
        }

        // Burst pattern recognition (repeated normalized messages)
        for (const auto &br : burstDetector.processEntry(entry))
        {
            core::Anomaly a(
                core::AnomalyType::SequenceViolation,
                core::AnomalySeverity::High,
                br.windowStart,
                br.windowEnd,
                br.score,
                br.description,
                br.source,
                br.samples);
            report.addAnomaly(std::move(a));
            ++ts[b].anomalies;
            ++emittedCount;
        }

        // Rare IP detection (IP extracted from message)
        for (const auto &iphit : ipDetector.processEntry(entry))
        {
            core::Anomaly a(
                core::AnomalyType::RarePattern,
                core::AnomalySeverity::Low,
                iphit.entry.timestamp(),
                iphit.entry.timestamp(),
                1.0,
                "Rare IP observed (count=" + std::to_string(iphit.count) + "): " + iphit.ip,
                iphit.entry.source(),
                {iphit.entry});
            report.addAnomaly(std::move(a));
            ++ts[b].anomalies;
            ++emittedCount;
        }
    }

    // -------------------------
    // Offline analyzer summaries (produce anomalies after seeing the whole file)
    // This also proves whether analyzers are actually wired into the pipeline.
    // -------------------------
    logger.debug("Running FrequencyAnalyzer on " + std::to_string(parsedCount) + " events...");
    const auto freqAnoms = freq.detectAnomalies();
    logger.info("FrequencyAnalyzer produced " + std::to_string(freqAnoms.size()) + " anomalies");
    for (const auto &d : freqAnoms)
    {
        core::Anomaly a(core::AnomalyType::FrequencySpike, core::AnomalySeverity::Medium,
                        haveTimeRange ? minTs : core::Report::Clock::now(),
                        haveTimeRange ? maxTs : core::Report::Clock::now(),
                        1.0, d, std::nullopt, {});
        report.addAnomaly(std::move(a));
        ++emittedCount;
    }

    logger.debug("Running PatternAnalyzer on " + std::to_string(parsedCount) + " events...");
    const auto patAnoms = pattern.detectAnomalies();
    logger.info("PatternAnalyzer produced " + std::to_string(patAnoms.size()) + " anomalies");
    for (const auto &d : patAnoms)
    {
        core::Anomaly a(core::AnomalyType::SequenceViolation, core::AnomalySeverity::Medium,
                        haveTimeRange ? minTs : core::Report::Clock::now(),
                        haveTimeRange ? maxTs : core::Report::Clock::now(),
                        1.0, d, std::nullopt, {});
        report.addAnomaly(std::move(a));
        ++emittedCount;
    }

    logger.debug("Running TimeWindowAnalyzer detectAnomalies()...");
    const auto twAnoms = timeWindow.detectAnomalies();
    logger.info("TimeWindowAnalyzer produced " + std::to_string(twAnoms.size()) + " anomalies");
    for (const auto &tw : twAnoms)
    {
        // Map by description (simple but effective)
        core::AnomalyType type = core::AnomalyType::FrequencySpike;
        if (tw.description.find("Silence") != std::string::npos)
            type = core::AnomalyType::Silence;
        core::AnomalySeverity sev = (tw.score >= 0.9)   ? core::AnomalySeverity::High
                                    : (tw.score >= 0.6) ? core::AnomalySeverity::Medium
                                                        : core::AnomalySeverity::Low;
        core::Anomaly a(type, sev, tw.stats.windowStart, tw.stats.windowEnd, tw.score,
                        tw.description, std::nullopt, {});
        report.addAnomaly(std::move(a));
        ++emittedCount;
    }

    const auto wallEnd = std::chrono::steady_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(wallEnd - wallStart).count();

    report.setTotalEntries(parsedCount);
    if (haveTimeRange)
    {
        report.setAnalysisStart(minTs);
        report.setAnalysisEnd(maxTs);
    }
    else
    {
        // No parsed entries; fall back to "now"
        const auto now = core::Report::Clock::now();
        report.setAnalysisStart(now);
        report.setAnalysisEnd(now);
    }

    logger.info("Parsed entries: " + std::to_string(parsedCount));
    logger.info("Finished in " + std::to_string(ms) + " ms");

    // Console report
    {
        LogTool::Report::ConsoleReporter console(LogTool::Report::ConsoleReporter::Verbosity::VERBOSE);
        console.generateReport(report);
    }

    // JSON export
    if (opts.json)
    {
        LogTool::Report::JsonReporter json(LogTool::Report::JsonReporter::PrettyPrint::PRETTY);
        json.generateReport(report);

        const std::string jsonPath = opts.outputDir + "/analysis-report.json";
        std::ofstream out(jsonPath);
        if (!out.is_open())
        {
            logger.error("Cannot write JSON: " + jsonPath);
        }
        else
        {
            json.writeJson(out);
            logger.info("JSON saved: " + jsonPath);
        }
    }

    // CSV export
    if (opts.csv)
    {
        LogTool::Report::CsvReporter csv(LogTool::Report::CsvReporter::ExportMode::ANOMALIES_ONLY);
        csv.generateReport(report);

        const std::string csvPath = opts.outputDir + "/analysis-report.csv";
        std::ofstream out(csvPath);
        if (!out.is_open())
        {
            logger.error("Cannot write CSV: " + csvPath);
        }
        else
        {
            csv.writeCsv(out, true);
            logger.info("CSV saved: " + csvPath);
        }
    }

    // Graph/time-series export

    if (opts.graphs)
    {
        // Create a dedicated graphs folder inside outputDir
        const auto now = std::chrono::system_clock::now();
        const std::time_t nowT = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#if defined(_WIN32)
        localtime_s(&tm, &nowT);
#else
        localtime_r(&nowT, &tm);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm, "graphs_%Y%m%d_%H%M%S");
        const std::string graphsDir = opts.outputDir + "/" + oss.str();

        try
        {
            std::filesystem::create_directories(graphsDir);
        }
        catch (...)
        { /* ignore */
        }

        // 1) Time-series per minute CSV
        const std::string tsPath = opts.outputDir + "/timeseries_per_minute.csv";
        {
            std::ofstream out(tsPath);
            if (!out.is_open())
            {
                logger.error("Cannot write timeseries: " + tsPath);
            }
            else
            {
                out << "minute_iso,total,trace,debug,info,warn,error,critical,unknown,anomalies,malformed\n";
                for (const auto &kv : ts)
                {
                    const std::time_t t = kv.first;
                    const auto &s = kv.second;
                    const auto tp = core::LogEntry::Clock::from_time_t(t);
                    out << LogTool::Utils::toIso8601(tp) << ","
                        << s.total << "," << s.trace << "," << s.debug << "," << s.info << ","
                        << s.warn << "," << s.error << "," << s.critical << "," << s.unknown << ","
                        << s.anomalies << "," << s.malformed << "\n";
                }
                logger.info("Time-series CSV saved: " + tsPath);
            }
        }

        // 2) Full entries CSV (for message/service/IP frequency plots)
        const std::string entriesPath = opts.outputDir + "/entries.csv";
        {
            std::ofstream out(entriesPath);
            if (!out.is_open())
            {
                logger.error("Cannot write entries CSV: " + entriesPath);
            }
            else
            {
                out << "timestamp_iso,level,source,message\n";
                file.clear();
                file.seekg(0, std::ios::beg);

                std::string ln;
                while (std::getline(file, ln))
                {
                    if (ln.empty())
                        continue;
                    auto pr = parser.parseLineDetailed(ln);
                    if (!pr.entry.has_value())
                        continue;

                    const auto &e = *pr.entry;

                    auto levelToStr = [](core::LogLevel lv) -> const char *
                    {
                        switch (lv)
                        {
                        case core::LogLevel::Trace:
                            return "TRACE";
                        case core::LogLevel::Debug:
                            return "DEBUG";
                        case core::LogLevel::Info:
                            return "INFO";
                        case core::LogLevel::Warn:
                            return "WARN";
                        case core::LogLevel::Error:
                            return "ERROR";
                        case core::LogLevel::Critical:
                            return "CRITICAL";
                        default:
                            return "UNKNOWN";
                        }
                    };

                    const std::string tsIso = LogTool::Utils::toIso8601(e.timestamp());
                    const std::string src = e.source().value_or("unknown");
                    const std::string msg = e.message();

                    // Use std::quoted for safe CSV writing (adds quotes and escapes quotes)
                    out << std::quoted(tsIso) << ","
                        << std::quoted(levelToStr(e.level())) << ","
                        << std::quoted(src) << ","
                        << std::quoted(msg)
                        << "\n";
                }
                logger.info("Entries CSV saved: " + entriesPath);
            }
        }

        // 3) Benchmark CSV (appends one row per run)
        const std::string benchPath = opts.outputDir + "/benchmark_runs.csv";
        try
        {
            const std::uintmax_t fsz = std::filesystem::file_size(opts.inputFile);
            const auto wallEnd = std::chrono::steady_clock::now();
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(wallEnd - wallStart).count();

            const bool fileExists = std::filesystem::exists(benchPath);
            std::ofstream out(benchPath, std::ios::app);
            if (out.is_open())
            {
                if (!fileExists)
                    out << "run_time_iso,file_size_bytes,wall_ms,parsed,malformed,emitted_anomalies\n";
                out << std::quoted(LogTool::Utils::toIso8601(core::Report::Clock::now())) << ","
                    << fsz << "," << ms << ","
                    << parsedCount << "," << malformedCount << "," << emittedCount << "\n";
                logger.info("Benchmark CSV updated: " + benchPath);
            }
        }
        catch (...)
        { /* ignore */
        }

        // 4) Python plotting script (generates many graphs into graphsDir)
        const std::string pyPath = graphsDir + "/plot_all_graphs.py";
        {
            std::ofstream py(pyPath);
            if (!py.is_open())
            {
                logger.error("Cannot write plot script: " + pyPath);
            }
            else
            {
                py << R"PY(
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
)PY";
                logger.info("Plot script saved: " + pyPath);
            }
        }

        // 5) Best-effort auto-run plot script (optional).
        // If python isn't available, user can run manually:
        //   python plot_all_graphs.py  (inside the graphs folder)
        try
        {
#if defined(_WIN32)
            const std::string cmd1 = "python \"" + pyPath + "\"";
            const std::string cmd2 = "python3 \"" + pyPath + "\"";
#else
            const std::string cmd1 = "python3 \"" + pyPath + "\"";
            const std::string cmd2 = "python \"" + pyPath + "\"";
#endif
            int rc = std::system(cmd1.c_str());
            if (rc != 0)
                (void)std::system(cmd2.c_str());
        }
        catch (...)
        { /* ignore */
        }
    }

    // Summary generator
    {
        LogTool::Report::ReportGenerator gen(LogTool::Report::ReportGenerator::OutputFormat::SUMMARY);
        gen.generateReport(report);
        logger.info("ANALYSIS SUMMARY:\n" + gen.getReportString());
    }

    const std::size_t anomalyCount = report.anomalies().size();
    if (anomalyCount == 0)
        return 0;
    if (anomalyCount > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        return std::numeric_limits<int>::max();
    return static_cast<int>(anomalyCount);
}