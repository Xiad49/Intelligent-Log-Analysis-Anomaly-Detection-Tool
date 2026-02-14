// File: C:\Project\include\core/Anomaly.hpp
//
// Core data model representing a detected anomaly in the log stream.
// This class is used by different anomaly detector implementations
// (rule-based, statistical, spike-based) and passed to reporting modules.

#ifndef CORE_ANOMALY_HPP
#define CORE_ANOMALY_HPP

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <optional>

#include "core/LogEntry.hpp"  // Adjust include path if your project uses a different layout.

namespace core
{

/**
 * @brief High-level category of an anomaly.
 *
 * Keeping this small and generic allows multiple detector
 * implementations to map their internal logic into a common
 * representation that reporting modules can understand.
 */
enum class AnomalyType : std::uint8_t
{
    FrequencySpike = 0,   ///< Sudden increase in event frequency.
    RarePattern,          ///< Rare or previously unseen pattern.
    StatisticalOutlier,   ///< Statistically abnormal behavior (e.g., Z-score).
    SequenceViolation,    ///< Abnormal order or missing/extra events.
    Silence,              ///< Unexpected disappearance of activity.
    Other                 ///< Catch-all for custom detector types.
};

/**
 * @brief Severity level assigned to a detected anomaly.
 *
 * This is separate from per-log-entry severity; it reflects
 * how critical the *anomaly* is from a system perspective.
 */
enum class AnomalySeverity : std::uint8_t
{
    Low = 0,
    Medium,
    High,
    Critical
};

/**
 * @brief Core anomaly representation.
 *
 * Responsibilities:
 *  - Capture where and when the anomaly occurred.
 *  - Store detector-specific scores (e.g., Z-score, deviation).
 *  - Provide enough context for reporting and downstream tools
 *    without embedding heavy business logic here.
 *
 * Design notes:
 *  - Value type with RAII via standard members only.
 *  - Uses std::chrono for timestamps.
 *  - Uses std::vector and std::string from STL for flexible context.
 *  - Thread-safe as long as instances are not mutated concurrently.
 */
class Anomaly
{
public:
    using Clock     = std::chrono::system_clock;
    using TimePoint = std::chrono::time_point<Clock>;

    /**
     * @brief Default-constructed anomaly is "empty" and non-critical.
     *
     * Intended mostly for container compatibility and test scaffolding.
     */
    Anomaly() = default;

    /**
     * @brief Construct a fully described anomaly.
     *
     * @param type High-level anomaly category.
     * @param severity Assessed impact level.
     * @param windowStart Start of the time window where anomaly was detected.
     * @param windowEnd End of the time window where anomaly was detected.
     * @param score Detector-specific score (e.g., Z-score, spike ratio).
     * @param description Human-readable explanation.
     * @param source Optional logical source (service/module) if known.
     * @param relatedEntries Optional sample of log entries that illustrate the anomaly.
     */
    Anomaly(AnomalyType type,
            AnomalySeverity severity,
            TimePoint windowStart,
            TimePoint windowEnd,
            double score,
            std::string description,
            std::optional<std::string> source = std::nullopt,
            std::vector<LogEntry> relatedEntries = {})
        : m_type(type),
          m_severity(severity),
          m_windowStart(windowStart),
          m_windowEnd(windowEnd),
          m_score(score),
          m_description(std::move(description)),
          m_source(std::move(source)),
          m_relatedEntries(std::move(relatedEntries))
    {
    }

    // Defaulted value semantics for easy use with STL containers.
    Anomaly(const Anomaly&)            = default;
    Anomaly(Anomaly&&) noexcept        = default;
    Anomaly& operator=(const Anomaly&) = default;
    Anomaly& operator=(Anomaly&&) noexcept = default;

    ~Anomaly() = default;

    // ---------- Accessors ----------

    AnomalyType type() const noexcept
    {
        return m_type;
    }

    AnomalySeverity severity() const noexcept
    {
        return m_severity;
    }

    const TimePoint& windowStart() const noexcept
    {
        return m_windowStart;
    }

    const TimePoint& windowEnd() const noexcept
    {
        return m_windowEnd;
    }

    /**
     * @brief Detector-specific anomaly score.
     *
     * Interpretation depends on detector:
     *  - Statistical detector: Z-score or similar.
     *  - Spike detector: ratio vs. baseline.
     *  - Rule-based detector: custom scoring function.
     */
    double score() const noexcept
    {
        return m_score;
    }

    /**
     * @brief Human-readable explanation for reports.
     *
     * Example: "Error rate for service X spiked 5x above baseline".
     */
    const std::string& description() const noexcept
    {
        return m_description;
    }

    /**
     * @brief Optional logical source associated with the anomaly.
     *
     * Often mapped from log entry sources (service/component).
     */
    const std::optional<std::string>& source() const noexcept
    {
        return m_source;
    }

    /**
     * @brief Sample of log entries that contributed to this anomaly.
     *
     * Reporting modules can show a small subset to help operators
     * understand and validate the anomaly.
     */
    const std::vector<LogEntry>& relatedEntries() const noexcept
    {
        return m_relatedEntries;
    }

    // ---------- Mutators (kept minimal and explicit) ----------

    void setSeverity(AnomalySeverity severity) noexcept
    {
        m_severity = severity;
    }

    void setDescription(std::string desc)
    {
        m_description = std::move(desc);
    }

    void setSource(std::optional<std::string> src)
    {
        m_source = std::move(src);
    }

    void addRelatedEntry(const LogEntry& entry)
    {
        m_relatedEntries.push_back(entry);
    }

private:
    AnomalyType             m_type{AnomalyType::Other};         ///< Category of anomaly.
    AnomalySeverity         m_severity{AnomalySeverity::Low};   ///< Impact level.
    TimePoint               m_windowStart{};                    ///< Time window start.
    TimePoint               m_windowEnd{};                      ///< Time window end.
    double                  m_score{0.0};                       ///< Detector-specific score.
    std::string             m_description;                      ///< Human-readable explanation.
    std::optional<std::string> m_source;                        ///< Optional logical source.
    std::vector<LogEntry>   m_relatedEntries;                   ///< Contextual log entries.
};

} // namespace core

#endif // CORE_ANOMALY_HPP
