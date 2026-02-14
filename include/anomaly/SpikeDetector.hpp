#pragma once

#include <deque>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <string>
#include "core/LogEntry.hpp"
#include "core/Anomaly.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
    namespace Anomaly
    {
        /**
         * SpikeDetector
         *
         * Responsibilities:
         *  - Detect sudden frequency spikes (Sudden spikes from project spec)
         *  - Identify burst anomalies (high event density in short time)
         *  - Track rate-of-change anomalies (rapid increases)
         *  - Compare current window against historical baselines
         *
         * Design notes:
         *  - Uses multiple sliding windows (short/medium/long term)
         *  - Computes spike ratio (current / historical average)
         *  - Thread-safe for concurrent log processing
         *  - Per-source spike detection prevents cross-service false positives
         */
        class SpikeDetector
        {
        public:
            struct SpikeStats
            {
                std::size_t currentCount = 0;
                std::size_t baselineCount = 0;
                double spikeRatio = 1.0;      // current / baseline
                double rateOfChange = 0.0;    // (current - previous) / previous
                Utils::TimePoint windowStart;
                Utils::TimePoint windowEnd;
                std::string source;
            };

            struct SpikeAnomaly
            {
                std::string description;
                double severity;              // 0.0-1.0
                SpikeStats stats;
                std::vector<core::LogEntry> sampleEvents;
            };

            /// Default: detects 5x spikes over 60s baseline
            SpikeDetector();

            // Thread-safe but non-copyable due to window state
            SpikeDetector(const SpikeDetector&) = delete;
            SpikeDetector& operator=(const SpikeDetector&) = delete;
            SpikeDetector(SpikeDetector&&) = default;
            SpikeDetector& operator=(SpikeDetector&&) = default;

            /**
             * Process LogEntry and update spike detection windows.
             * Returns detected spikes immediately.
             * Thread-safe.
             */
            std::vector<SpikeAnomaly> processEntry(const core::LogEntry& entry);

            /**
             * Get spike statistics for specific source.
             * Thread-safe read access.
             */
            std::optional<SpikeStats> getStats(const std::string& source) const;

            /**
             * Check all sources for current spikes.
             */
            std::vector<SpikeAnomaly> checkAllSpikes() const;

            /**
             * Reset all spike detection windows.
             */
            void reset();

            // Configuration
            double spikeThreshold() const noexcept { return m_spikeThreshold; }
            void setSpikeThreshold(double ratio) noexcept;

            Utils::seconds shortWindow() const noexcept { return m_shortWindow; }
            void setShortWindow(Utils::seconds duration) noexcept;

            Utils::seconds baselineWindow() const noexcept { return m_baselineWindow; }
            void setBaselineWindow(Utils::seconds duration) noexcept;

            std::size_t maxSampleEvents() const noexcept { return m_maxSampleEvents; }
            void setMaxSampleEvents(std::size_t count) noexcept;

        private:
            /// Per-source spike tracking state
            struct SourceState
            {
                // Short-term window (current spike detection)
                std::deque<Utils::TimePoint> recentEvents;
                std::size_t currentCount = 0;
                
                // Baseline window (historical normal rate)
                std::deque<Utils::TimePoint> baselineEvents;
                std::size_t baselineCount = 0;
                
                // Previous window for rate-of-change
                std::size_t previousCount = 0;
                
                // Sample events for reporting
                std::vector<core::LogEntry> samples;
                
                Utils::TimePoint lastWindowAdvance;
            };

            /// Advance time windows and update counts
            void advanceWindows(SourceState& state, Utils::TimePoint now);

            /// Calculate spike ratio and rate of change
            SpikeStats calculateStats(const SourceState& state, 
                                    const std::string& source,
                                    Utils::TimePoint now) const;

            /// Determine if current activity represents a spike
            bool isSpike(const SpikeStats& stats) const;

            /// Generate anomaly report from spike detection
            SpikeAnomaly createAnomaly(const SpikeStats& stats, 
                                     const std::vector<core::LogEntry>& samples) const;

        private:
            mutable std::mutex m_mutex;

            // Per-source spike detection state
            std::unordered_map<std::string, SourceState> m_sourceStates;

            // Configuration parameters
            // Default tuned for this project's synthetic/anomalous logs.
            // 3x baseline tends to catch "moderate" but meaningful spikes.
            double m_spikeThreshold = 3.0;        // 3x baseline = spike
            Utils::seconds m_shortWindow = std::chrono::seconds(60);    // 1 minute current
            Utils::seconds m_baselineWindow = std::chrono::minutes(10); // 10 minute baseline
            std::size_t m_maxSampleEvents = 5;     // Max events to store per spike
        };

    } // namespace Anomaly
} // namespace LogTool
