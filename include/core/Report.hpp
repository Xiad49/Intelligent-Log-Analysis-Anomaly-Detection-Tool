// File: C:\Project\include\core/Report.hpp
//
// Core data model for representing analysis outcomes and detected anomalies.
// This is consumed by different reporters (console, JSON, CSV) and is
// produced by the analysis/anomaly detection layer.

#ifndef CORE_REPORT_HPP
#define CORE_REPORT_HPP

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <optional>
#include <map>

#include "core/LogEntry.hpp"
#include "core/Anomaly.hpp"

namespace core
{

/**
 * @brief Aggregated statistics per log level and per source.
 *
 * This struct is kept simple so it can be embedded inside Report
 * and used directly by reporting modules.
 */
struct LevelStats
{
    std::uint64_t count{0};          ///< Total events with this level.
    std::uint64_t anomalyCount{0};   ///< Anomalies associated with this level.
};

/**
 * @brief Summary of analysis for a particular source/component.
 */
struct SourceStats
{
    std::uint64_t totalEvents{0};    ///< Total events for this source.
    std::uint64_t errorEvents{0};    ///< Number of error/critical events.
    std::uint64_t warningEvents{0};  ///< Number of warning events.
};

/**
 * @brief High-level analysis report containing anomalies and statistics.
 *
 * Responsibilities:
 *  - Serve as a single, immutable-like snapshot of a completed analysis run.
 *  - Provide structured access to anomalies and aggregated metrics.
 *  - Stay independent of any particular output format (console/JSON/CSV).
 *
 * Design notes:
 *  - Value-type semantics with STL containers (std::vector, std::map).
 *  - No ownership of external resources; RAII via standard members.
 *  - Thread-safe for read-only access after construction.
 */
class Report
{
public:
    using Clock     = std::chrono::system_clock;
    using TimePoint = std::chrono::time_point<Clock>;

    /**
     * @brief Default constructor for an empty report.
     */
    Report() = default;

    /**
     * @brief Construct a report with core metadata.
     *
     * @param analysisStart When processing started.
     * @param analysisEnd When processing finished.
     * @param totalEntries Total number of processed log entries.
     * @param processedFile Optional file path or identifier of the log source.
     */
    Report(TimePoint analysisStart,
           TimePoint analysisEnd,
           std::uint64_t totalEntries,
           std::optional<std::string> processedFile = std::nullopt)
        : m_analysisStart(analysisStart),
          m_analysisEnd(analysisEnd),
          m_totalEntries(totalEntries),
          m_processedFile(std::move(processedFile))
    {
    }

    // Defaulted value semantics for easy interaction with STL containers.
    Report(const Report&)            = default;
    Report(Report&&) noexcept        = default;
    Report& operator=(const Report&) = default;
    Report& operator=(Report&&) noexcept = default;

    ~Report() = default;

    // ---------- Metadata accessors ----------

    const TimePoint& analysisStart() const noexcept
    {
        return m_analysisStart;
    }

    const TimePoint& analysisEnd() const noexcept
    {
        return m_analysisEnd;
    }

    std::uint64_t totalEntries() const noexcept
    {
        return m_totalEntries;
    }

    const std::optional<std::string>& processedFile() const noexcept
    {
        return m_processedFile;
    }

    // ---------- Metadata mutators (builder-style) ----------

    void setAnalysisStart(TimePoint tp) noexcept { m_analysisStart = tp; }
    void setAnalysisEnd(TimePoint tp) noexcept { m_analysisEnd = tp; }
    void setTotalEntries(std::uint64_t total) noexcept { m_totalEntries = total; }
    void setProcessedFile(std::optional<std::string> file) { m_processedFile = std::move(file); }

    // ---------- Anomaly data ----------

    std::vector<Anomaly>& anomalies() noexcept
    {
        return m_anomalies;
    }

    const std::vector<Anomaly>& anomalies() const noexcept
    {
        return m_anomalies;
    }

    void addAnomaly(const Anomaly& anomaly)
    {
        m_anomalies.push_back(anomaly);
    }

    void addAnomaly(Anomaly&& anomaly)
    {
        m_anomalies.emplace_back(std::move(anomaly));
    }

    /**
     * @brief Quick helper: total number of detected anomalies.
     */
    std::size_t anomalyCount() const noexcept
    {
        return m_anomalies.size();
    }

    // ---------- Level statistics ----------

    /**
     * @brief Access immutable map of statistics per log level.
     */
    const std::map<LogLevel, LevelStats>& levelStatistics() const noexcept
    {
        return m_levelStats;
    }

    /**
     * @brief Increment event count for a given log level.
     *
     * Intended to be called by analysis code as it processes entries.
     */
    void incrementLevelCount(LogLevel level, bool isAnomaly = false)
    {
        auto& stats = m_levelStats[level];
        ++stats.count;
        if (isAnomaly)
        {
            ++stats.anomalyCount;
        }
    }

    /**
     * @brief Increment anomaly count for a given log level (without incrementing event count).
     *
     * Use this when an entry is already counted via incrementLevelCount(), and you
     * later classify it as an anomaly (possibly multiple anomalies per entry).
     */
    void incrementAnomalyCount(LogLevel level)
    {
        auto& stats = m_levelStats[level];
        ++stats.anomalyCount;
    }

    // ---------- Source statistics ----------

    const std::map<std::string, SourceStats>& sourceStatistics() const noexcept
    {
        return m_sourceStats;
    }

    /**
     * @brief Update statistics for a particular source.
     *
     * @param source Source identifier (service/module).
     * @param level Severity level of the log entry.
     */
    void updateSourceStats(const std::string& source, LogLevel level)
    {
        auto& stats = m_sourceStats[source];
        ++stats.totalEvents;

        if (level == LogLevel::Error || level == LogLevel::Critical)
        {
            ++stats.errorEvents;
        }
        else if (level == LogLevel::Warn)
        {
            ++stats.warningEvents;
        }
    }

    // ---------- Global summary helpers ----------

    /**
     * @brief Convenience: compute the total number of error/critical events.
     *
     * This aggregates across all sources using cached SourceStats.
     */
    std::uint64_t totalErrorEvents() const noexcept
    {
        std::uint64_t total = 0;
        for (const auto& kv : m_sourceStats)
        {
            total += kv.second.errorEvents;
        }
        return total;
    }

    /**
     * @brief Convenience: compute the total number of warning events.
     */
    std::uint64_t totalWarningEvents() const noexcept
    {
        std::uint64_t total = 0;
        for (const auto& kv : m_sourceStats)
        {
            total += kv.second.warningEvents;
        }
        return total;
    }

private:
    // Core metadata.
    TimePoint                   m_analysisStart{};   ///< When analysis started.
    TimePoint                   m_analysisEnd{};     ///< When analysis finished.
    std::uint64_t               m_totalEntries{0};   ///< Number of processed log entries.
    std::optional<std::string>  m_processedFile;     ///< Path/identifier of the processed log file.

    // Detected anomalies.
    std::vector<Anomaly>        m_anomalies;

    // Aggregated statistics.
    std::map<LogLevel, LevelStats>  m_levelStats;    ///< Stats per log level.
    std::map<std::string, SourceStats> m_sourceStats;///< Stats per source component.
};

} // namespace core

#endif // CORE_REPORT_HPP
