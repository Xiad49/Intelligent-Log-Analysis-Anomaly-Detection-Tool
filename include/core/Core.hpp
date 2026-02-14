#ifndef CORE_HPP
#define CORE_HPP

#include <string>
#include <optional>
#include <vector>
#include <chrono>

namespace Core
{
    // Enumeration for different log levels
    enum class LogLevel
    {
        TRACE,
        DEBUG,
        INFO,
        WARN,
        ERROR,
        CRITICAL
    };

    // A simple struct representing a single log entry
    struct LogEntry
    {
        std::chrono::system_clock::time_point timestamp; // Log timestamp
        LogLevel level;                                  // Log level (e.g., INFO, ERROR)
        std::string source;                              // Source of the log (e.g., file or service name)
        std::string message;                             // The actual log message content

        // Constructor to easily create LogEntry objects
        LogEntry(std::chrono::system_clock::time_point ts, LogLevel lvl, std::string src, std::string msg)
            : timestamp(ts), level(lvl), source(std::move(src)), message(std::move(msg)) {}
    };

    // Utility functions to convert log level to string (for better output formatting)
    inline std::string logLevelToString(LogLevel level)
    {
        switch (level)
        {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARN: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
        }
    }

    // Utility function to parse a string into a LogLevel
    inline std::optional<LogLevel> stringToLogLevel(const std::string& levelStr)
    {
        if (levelStr == "TRACE") return LogLevel::TRACE;
        if (levelStr == "DEBUG") return LogLevel::DEBUG;
        if (levelStr == "INFO") return LogLevel::INFO;
        if (levelStr == "WARN") return LogLevel::WARN;
        if (levelStr == "ERROR") return LogLevel::ERROR;
        if (levelStr == "CRITICAL") return LogLevel::CRITICAL;
        return std::nullopt; // Invalid log level string
    }

    // Utility function to get the current time as a timestamp
    inline std::chrono::system_clock::time_point getCurrentTime()
    {
        return std::chrono::system_clock::now();
    }
} // namespace Core

#endif // CORE_HPP
