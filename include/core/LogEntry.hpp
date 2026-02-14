// File: C:\Project\include\core\LogEntry.hpp
//
// Core data model representing a single normalized log entry.
// This class is intentionally lightweight and value‑semantics friendly,
// so it can be stored in STL containers (e.g., std::vector, std::deque)
// and passed between analysis modules efficiently.

#ifndef CORE_LOG_ENTRY_HPP
#define CORE_LOG_ENTRY_HPP

#include <string>
#include <chrono>
#include <optional>
#include <cstdint>

namespace core
{

/**
 * @brief Enumeration of supported log severity levels.
 *
 * This covers the most common levels; parsers may map
 * format‑specific severities into this normalized set.
 */
enum class LogLevel : std::uint8_t
{
    Trace = 0,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
    Unknown  ///< Used when the original level cannot be parsed.
};

/**
 * @brief Lightweight, immutable-ish representation of a single log entry.
 *
 * Responsibilities:
 *  - Store normalized fields extracted by the input/parsing layer.
 *  - Provide accessors for analysis (frequency, time‑window, pattern).
 *  - Remain simple POD‑like to support high‑performance processing.
 *
 * Design notes:
 *  - Timestamps use std::chrono for type safety and portability.
 *  - Optional fields (like source) use std::optional to avoid
 *    ad‑hoc sentinel values.
 *  - The class manages only in‑memory data, so RAII is trivial:
 *    standard members are automatically cleaned up.
 */
class LogEntry
{
public:
    using Clock      = std::chrono::system_clock;
    using TimePoint  = std::chrono::time_point<Clock>;

    /**
     * @brief Construct an empty, invalid log entry.
     *
     * This is mainly for container compatibility.
     * Analysis code should generally work with valid entries
     * produced by the parser.
     */
    LogEntry() = default;

    /**
     * @brief Main constructor for a fully parsed log entry.
     *
     * @param timestamp Parsed timestamp (in system_clock).
     * @param level Normalized log level.
     * @param source Identifier of the component/service (optional).
     * @param message Raw or normalized log message body.
     * @param rawLine Original line text (optional, useful for reporting/debug).
     */
    LogEntry(TimePoint timestamp,
             LogLevel level,
             std::optional<std::string> source,
             std::string message,
             std::optional<std::string> rawLine = std::nullopt)
        : m_timestamp(timestamp),
          m_level(level),
          m_source(std::move(source)),
          m_message(std::move(message)),
          m_rawLine(std::move(rawLine))
    {
    }

    // Defaulted copy/move operations: value‑type semantics,
    // cheap to store in STL containers and pass by value when needed.
    LogEntry(const LogEntry&)            = default;
    LogEntry(LogEntry&&) noexcept        = default;
    LogEntry& operator=(const LogEntry&) = default;
    LogEntry& operator=(LogEntry&&) noexcept = default;

    ~LogEntry() = default; // RAII handled automatically by members.

    // ---------- Accessors ----------

    /**
     * @brief Get the timestamp associated with this log entry.
     */
    const TimePoint& timestamp() const noexcept
    {
        return m_timestamp;
    }

    /**
     * @brief Get the normalized log level.
     */
    LogLevel level() const noexcept
    {
        return m_level;
    }

    /**
     * @brief Get the source identifier (service/module), if available.
     */
    const std::optional<std::string>& source() const noexcept
    {
        return m_source;
    }

    /**
     * @brief Get the parsed log message text.
     */
    const std::string& message() const noexcept
    {
        return m_message;
    }

    /**
     * @brief Get the original raw log line, if the parser preserved it.
     *
     * Keeping the raw line is useful for:
     *  - Detailed anomaly reports
     *  - Debugging parsing issues
     */
    const std::optional<std::string>& rawLine() const noexcept
    {
        return m_rawLine;
    }

    // ---------- Convenience Methods ----------

    /**
     * @brief Check if this entry carries a valid timestamp.
     *
     * For this project, we assume parser always sets a timestamp.
     * However, this method is left in place in case future formats
     * allow missing/invalid timestamps.
     */
    bool hasValidTimestamp() const noexcept
    {
        // Currently always true; placeholder for future logic.
        return true;
    }

    /**
     * @brief Return true if this log entry likely represents an error.
     *
     * This is a lightweight heuristic used by some analyzers to
     * quickly filter error‑like entries without re‑encoding the logic.
     */
    bool isErrorLike() const noexcept
    {
        return m_level == LogLevel::Error ||
               m_level == LogLevel::Critical;
    }

private:
    // Core structured fields used across the analysis and anomaly modules.
    TimePoint                 m_timestamp{};          ///< Event time (normalized).
    LogLevel                  m_level{LogLevel::Unknown}; ///< Severity level.
    std::optional<std::string> m_source;             ///< Service / component name.
    std::string               m_message;             ///< Parsed message body.
    std::optional<std::string> m_rawLine;           ///< Original line (optional).
};

} // namespace core

#endif // CORE_LOG_ENTRY_HPP
