#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <memory>
#include <vector>


#include "../core/LogEntry.hpp"
// Bridge: core headers use LogTool::core (lowercase). Allow Core::... in this module.
namespace LogTool { namespace Core = core; }
#include "FileReader.hpp"
#include "../utils/StringUtils.hpp"
#include "../utils/TimeUtils.hpp"

namespace LogTool
{
    namespace Input
    {
        /**
         * LogParser
         *
         * Responsibilities:
         *  - Parse raw log lines into structured LogEntry objects.
         *  - Handle multiple common log formats with configurable patterns.
         *  - Gracefully skip malformed log entries (reliability).
         *
         * Design notes:
         *  - Stateless parsing logic (thread-safe).
         *  - Supports configurable parsing rules via patterns.
         *  - Works with FileReader's streaming interface.
         *  - Returns std::optional<LogEntry> to indicate parse success/failure.
         */
        class LogParser
        {
        public:
            // Detailed parse result used to track malformed lines and JSON-vs-text parsing.
            // parseLine() remains backward-compatible and returns only the parsed entry.
            struct ParseResult
            {
                std::optional<Core::LogEntry> entry;
                bool wasJson = false;
                bool malformed = false;
                std::string error; // best-effort parse error
            };

            /// Default constructor with common log format patterns.
            LogParser();

            // Stateless and copyable (all parsing is pure functions).
            LogParser(const LogParser &)            = default;
            LogParser &operator=(const LogParser &) = default;

            LogParser(LogParser &&)                 = default;
            LogParser &operator=(LogParser &&)      = default;

            /**
             * Parse a single raw log line into a LogEntry.
             *
             * Returns std::nullopt if the line cannot be parsed with any known pattern.
             * Successfully parsed entries are normalized (timestamps, trimmed fields).
             */
            std::optional<Core::LogEntry> parseLine(std::string_view rawLine) const;

            /**
             * Parse a line and return diagnostics.
             *
             * - If parsing succeeds: result.entry has value.
             * - If parsing fails: result.malformed=true and result.error contains a hint.
             * - If the line is JSON: result.wasJson=true (success or failure).
             */
            ParseResult parseLineDetailed(std::string_view rawLine) const;

            /**
             * Parse lines directly from a FileReader stream.
             *
             * Convenience method that calls nextLine() and parseLine() internally.
             * Returns std::nullopt on EOF, error, or parse failure.
             */
            std::optional<Core::LogEntry> parseNext(FileReader &reader) const;

            /**
             * Add a custom parsing pattern.
             *
             * Format: "TIMESTAMP LEVEL SOURCE: MESSAGE"
             * Example patterns the parser tries:
             *   - "2023-10-03 14:23:45 INFO app1: User login failed"
             *   - "[2023-10-03T14:23:45] ERROR database Connection timeout"
             */
            void addPattern(std::string pattern);

            /// Clear all parsing patterns (use only custom ones).
            void clearPatterns();

            /// Get the current set of parsing patterns (for debugging/config).
            const std::vector<std::string>& patterns() const noexcept;

        private:
            // Lightweight JSON extraction helpers (no external JSON dependency).
            std::optional<Core::LogEntry> tryParseJsonLine(std::string_view line, std::string* errOut) const;
            static std::optional<std::string> extractJsonString(std::string_view json, std::string_view key);
            static std::optional<std::string> extractJsonRaw(std::string_view json, std::string_view key);
            static std::string_view trimSv(std::string_view s);
            /// Try to parse a specific log format pattern from the line.
            std::optional<Core::LogEntry> tryParsePattern(
                std::string_view line,
                std::string_view pattern) const;

            /// Extract timestamp using common formats.
            std::optional<Utils::TimePoint> extractTimestamp(std::string_view line) const;

            /// Extract log level from common level strings.
            std::optional<Core::LogLevel> extractLevel(std::string_view line) const;

            /// Extract source/service name (before colon or in brackets).
            std::optional<std::string> extractSource(std::string_view line) const;

            /// Extract the main message content.
            std::optional<std::string> extractMessage(std::string_view line) const;

        private:
            std::vector<std::string> m_patterns;
        };

    } // namespace Input
} // namespace LogTool
