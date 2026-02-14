#pragma once

#include <chrono>
#include <ctime>
#include <string>
#include <string_view>
#include <optional>
#include <cstdint>
#include <stdexcept>
#include <array>

namespace LogTool
{
    namespace Utils
    {
        /**
         * Time utilities for log parsing, normalization, and time-window analysis.
         *
         * Design goals:
         *  - Use std::chrono types for strong typing and precision.
         *  - Avoid global mutable state; all functions are thread-safe.
         *  - Provide simple conversion utilities for timestamps used across the pipeline.
         *
         * Notes:
         *  - We use system_clock for wall-clock timestamps coming from logs.
         *  - Parsing functions return std::optional to signal failures instead of throwing.
         */

        using Clock        = std::chrono::system_clock;
        using TimePoint    = std::chrono::time_point<Clock>;
        using milliseconds = std::chrono::milliseconds;
        using seconds      = std::chrono::seconds;

        /// Convert a time_t to TimePoint (system_clock).
        TimePoint from_time_t(std::time_t t) noexcept;

        /// Convert a TimePoint to time_t (second precision).
        std::time_t to_time_t(TimePoint tp) noexcept;

        /**
         * Get current system time as TimePoint.
         * Useful for measuring analysis duration and generating report timestamps.
         */
        TimePoint now() noexcept;

        /**
         * Format a TimePoint into a human-readable timestamp string.
         *
         * Default format: "YYYY-MM-DD HH:MM:SS"
         * This is suitable for console/JSON/CSV reporting.
         */
        std::string formatTimestamp(TimePoint tp,
                                     std::string_view format = "%Y-%m-%d %H:%M:%S");

        /**
         * Format a TimePoint as ISO-8601-like string: "YYYY-MM-DDTHH:MM:SS".
         * Useful for machine-readable logs and JSON output.
         */
        std::string toIso8601(TimePoint tp);

        /**
         * Parse a timestamp in the common log format "YYYY-MM-DD HH:MM:SS".
         *
         * Returns std::nullopt if parsing fails.
         * This is a good default for normalized internal timestamps.
         */
        std::optional<TimePoint> parseTimestamp(std::string_view sv);

        /**
         * Parse a UNIX timestamp (seconds since epoch) string.
         *
         * This is useful when logs already store timestamps as epoch seconds.
         */
        std::optional<TimePoint> parseUnixSeconds(std::string_view sv);

        /**
         * Convert a TimePoint to milliseconds since epoch.
         *
         * This is convenient for storing numeric timestamps or computing durations.
         */
        std::int64_t toMillisSinceEpoch(TimePoint tp) noexcept;

        /// Convert milliseconds since epoch back to TimePoint.
        TimePoint fromMillisSinceEpoch(std::int64_t ms) noexcept;

        /// Compute the duration between two time points in milliseconds.
        std::int64_t diffMillis(TimePoint start, TimePoint end) noexcept;

        /// Compute the duration between two time points in seconds (integer).
        std::int64_t diffSeconds(TimePoint start, TimePoint end) noexcept;

        /**
         * Check if a timestamp lies within a half-open time window [windowStart, windowEnd).
         * Used by time-window based analyzers to select relevant events.
         */
        bool inWindow(TimePoint ts,
                       TimePoint windowStart,
                       TimePoint windowEnd) noexcept;

        /**
         * Advance a time window by a given duration.
         *
         * This can be useful for sliding-window algorithms in time-based analysis.
         */
        template <typename Duration>
        void advanceWindow(TimePoint &windowStart,
                           TimePoint &windowEnd,
                           Duration step) noexcept;

        /**
         * Simple scoped timer utility (RAII) to measure elapsed wall-clock time
         * of a code block, e.g., for performance tests.
         *
         * Usage:
         *  {
         *      ScopedTimer timer(startTimePoint);
         *      // work...
         *  }
         *  // now startTimePoint holds the time when the scope ended.
         *
         * You can adapt this to integrate with a Logger if needed.
         */
        class ScopedTimer
        {
        public:
            explicit ScopedTimer(TimePoint &target) noexcept;
            ScopedTimer(const ScopedTimer &)            = delete;
            ScopedTimer &operator=(const ScopedTimer &) = delete;
            ScopedTimer(ScopedTimer &&other) noexcept;
            ScopedTimer &operator=(ScopedTimer &&) = delete;
            ~ScopedTimer() noexcept;

        private:
            TimePoint &target_;
            TimePoint  start_;
            bool       moved_ { false };
        };

    } // namespace Utils
} // namespace LogTool
