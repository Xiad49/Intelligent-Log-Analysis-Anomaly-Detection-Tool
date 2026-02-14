#pragma once

#include <chrono>
#include <deque>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <string>
#include "../core/LogEntry.hpp"   // Ensure correct path to LogEntry.hpp
#include "../utils/TimeUtils.hpp"

namespace LogTool
{
    namespace Analysis
    {
        class TimeWindowAnalyzer
        {
        public:
            struct WindowStats
            {
                std::size_t totalEvents = 0;
                std::size_t errorEvents = 0;
                double errorRate = 0.0;  // errors / total
                std::unordered_map<std::string, std::size_t> eventsBySource;
                Utils::TimePoint windowStart;
                Utils::TimePoint windowEnd;
            };

            struct Anomaly
            {
                std::string description;
                double score;  // 0.0-1.0 severity
                WindowStats stats;
            };

            TimeWindowAnalyzer();

            // Thread-safe but non-copyable/moveable due to internal state
            TimeWindowAnalyzer(const TimeWindowAnalyzer&) = delete;
            TimeWindowAnalyzer& operator=(const TimeWindowAnalyzer&) = delete;
            TimeWindowAnalyzer(TimeWindowAnalyzer&&) = delete;
            TimeWindowAnalyzer& operator=(TimeWindowAnalyzer&&) = delete;

            // Add LogEntry to current time window.
            void addEntry(const core::LogEntry& entry);

            // Get statistics for the most recent complete window.
            WindowStats currentWindowStats() const;

            // Detect anomalies in current/recent windows.
            std::vector<Anomaly> detectAnomalies() const;

            // Advance to next time window (for fixed-interval analysis).
            void advanceWindow(Utils::seconds windowSize);

            // Reset analysis (clear all windows and history).
            void reset();

            // Configuration accessors
            Utils::seconds windowSize() const noexcept { return m_windowSize; }
            void setWindowSize(Utils::seconds size) noexcept;

            double errorRateThreshold() const noexcept { return m_errorRateThreshold; }
            void setErrorRateThreshold(double threshold) noexcept;

            std::size_t burstThreshold() const noexcept { return m_burstThreshold; }
            void setBurstThreshold(std::size_t count) noexcept;

            std::size_t silenceThreshold() const noexcept { return m_silenceThreshold.count(); }
            void setSilenceThreshold(Utils::seconds duration) noexcept;

        private:
            struct TimedEvent
            {
                Utils::TimePoint timestamp;
                core::LogLevel level;  // Fixed: add level here
                std::string source;
            };

            struct TimeBucket
            {
                Utils::TimePoint start;
                Utils::TimePoint end;
                std::deque<TimedEvent> events;
                std::unordered_map<std::string, std::size_t> sourceCounts;
            };

            void addEventUnlocked(const core::LogEntry& entry);

            void evictOldEvents(TimeBucket& bucket);

            WindowStats calculateStats(const TimeBucket& bucket) const;

            Anomaly checkErrorSpike(const TimeBucket& bucket) const;
            Anomaly checkBurst(const TimeBucket& bucket) const;
            Anomaly checkSilence(const TimeBucket& bucket) const;

        private:
            mutable std::mutex m_mutex;
            TimeBucket m_currentWindow;
            std::deque<TimeBucket> m_windowHistory;

            bool m_initialized = false; // aligns windows to log timestamps

            Utils::seconds m_windowSize = std::chrono::seconds(60);  // 1 minute
            double m_errorRateThreshold = 0.5;                       // 50% errors
            std::size_t m_burstThreshold = 100;                      // 100 events
            Utils::seconds m_silenceThreshold = std::chrono::seconds(300); // 5 min silence
            std::size_t m_maxHistoryWindows = 12;                    // ~12 minutes
        };

    } // namespace Analysis
} // namespace LogTool
