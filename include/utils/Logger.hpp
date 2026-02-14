#pragma once

#include <string>
#include <string_view>
#include <fstream>
#include <mutex>
#include <memory>
#include <ostream>

#include "utils/TimeUtils.hpp"  // for TimePoint and formatting

namespace LogTool
{
    namespace Utils
    {
        /**
         * Log severity levels used across the system.
         *
         * Typical usage:
         *  - TRACE: very verbose, internal debugging
         *  - DEBUG: debug information for developers
         *  - INFO: high-level application flow
         *  - WARN: unusual situations, not yet errors
         *  - ERROR: recoverable errors
         *  - CRITICAL: unrecoverable failures, likely to terminate
         */
        enum class LogLevel
        {
            TRACE    = 0,
            DEBUG    = 1,
            INFO     = 2,
            WARN     = 3,
            ERROR    = 4,
            CRITICAL = 5,
        };

        /**
         * Logger
         *
         * Thread-safe, minimal logging facility suitable for:
         *  - Instrumenting pipeline stages (parsing, analysis, detection, reporting).
         *  - Emitting performance and anomaly summaries.
         *
         * Features:
         *  - Global log level filtering.
         *  - Optional log file in addition to stderr.
         *  - Timestamps on every message.
         *
         * This class is non-copyable and intended to be owned as a singleton
         * or shared_ptr in your main application.
         */
        class Logger
        {
        public:
            /// Create a logger that writes to stderr only.
            Logger();

            /**
             * Create a logger with optional file output.
             *
             * If filePath is non-empty, the logger attempts to open the file
             * in append mode. If opening fails, logging silently falls back
             * to stderr only.
             */
            explicit Logger(std::string_view filePath, LogLevel level = LogLevel::INFO);

            // Non-copyable, but movable.
            Logger(const Logger &)            = delete;
            Logger &operator=(const Logger &) = delete;

            Logger(Logger &&) noexcept;
            Logger &operator=(Logger &&) noexcept;

            ~Logger();

            /// Set the minimum severity that will be logged.
            void setLevel(LogLevel level) noexcept;

            /// Get the currently configured minimum severity.
            LogLevel level() const noexcept;

            /// Check quickly whether this level would be logged.
            bool isEnabled(LogLevel level) const noexcept;

            /**
             * Log a message with a given severity.
             *
             * Thread-safe: uses an internal mutex to serialize writes.
             * The log entry includes:
             *   - Timestamp (using TimeUtils)
             *   - Log level
             *   - Message text
             */
            void log(LogLevel level, std::string_view message);

            /// Convenience wrappers for common severities.
            void trace(std::string_view message)   { log(LogLevel::TRACE, message); }
            void debug(std::string_view message)   { log(LogLevel::DEBUG, message); }
            void info(std::string_view message)    { log(LogLevel::INFO,  message); }
            void warn(std::string_view message)    { log(LogLevel::WARN,  message); }
            void error(std::string_view message)   { log(LogLevel::ERROR, message); }
            void critical(std::string_view message){ log(LogLevel::CRITICAL, message); }

        private:
            /// Helper to convert level to string, e.g., "INFO".
            static const char *toString(LogLevel level) noexcept;

            /// Write a fully formatted line to the active sinks.
            void writeLine(std::string_view line);

        private:
            LogLevel                        m_level;
            std::ofstream                   m_file;       // RAII-managed file handle
            bool                            m_fileEnabled;
            std::ostream                   *m_console;    // usually &std::cerr
            mutable std::mutex              m_mutex;      // protects all writes
        };

        /**
         * Global logger accessor.
         *
         * You can implement this (in Logger.cpp) as a function returning
         * a process-wide Logger instance, e.g., a static local.
         *
         * Example usage:
         *   Logger &log = getLogger();
         *   log.info("Started analysis");
         */
        Logger &getLogger();

    } // namespace Utils
} // namespace LogTool
