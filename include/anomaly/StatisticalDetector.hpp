#pragma once

#include <vector>
#include <deque>
#include <unordered_map>
#include <mutex>
#include <cmath>
#include "../core/LogEntry.hpp"
#include "../core/Anomaly.hpp"
#include "../utils/TimeUtils.hpp"

namespace LogTool
{
    namespace Anomaly
    {
        /**
         * StatisticalDetector
         *
         * Responsibilities:
         *  - Statistical anomaly detection using:
         *    - Z-score analysis (mean ± N*stddev)
         *    - Moving average deviation
         *    - Event frequency distribution analysis
         *  - Online learning (adapts to changing baselines)
         *  - Per-source statistical models
         *
         * Design notes:
         *  - Uses Welford's algorithm for online mean/variance calculation
         *  - Thread-safe for concurrent log processing
         *  - Maintains per-source statistics for accurate detection
         *  - Configurable Z-score thresholds and window sizes
         */
        class StatisticalDetector
        {
        public:
            struct Stats
            {
                double mean = 0.0;
                double stddev = 0.0;
                double zscore = 0.0;
                std::size_t count = 0;
                double movingAverage = 0.0;
                Utils::TimePoint lastUpdate;
            };

            struct Anomaly
            {
                std::string description;
                double zscore;
                double severity;  // 0.0-1.0
                Stats stats;
                core::LogEntry entry;
            };

            /// Default: 3-sigma detection, 100-event window
            StatisticalDetector();

            // Thread-safe but non-copyable due to statistical state
            StatisticalDetector(const StatisticalDetector&) = delete;
            StatisticalDetector& operator=(const StatisticalDetector&) = delete;
            StatisticalDetector(StatisticalDetector&&) = default;
            StatisticalDetector& operator=(StatisticalDetector&&) = default;

            /**
             * Process LogEntry and update statistical models.
             * Returns anomalies if detected.
             * Thread-safe.
             */
            std::vector<Anomaly> processEntry(const core::LogEntry& entry);

            /**
             * Get statistical summary for specific source.
             * Thread-safe read access.
             */
            std::optional<Stats> getStats(const std::string& source) const;

            /**
             * Get global statistics across all sources.
             */
            std::unordered_map<std::string, Stats> getAllStats() const;

            /**
             * Detect outliers in current statistical models.
             */
            std::vector<Anomaly> detectCurrentAnomalies() const;

            /**
             * Reset all statistical models.
             */
            void reset();

            // Configuration
            double zScoreThreshold() const noexcept { return m_zScoreThreshold; }
            void setZScoreThreshold(double threshold) noexcept;

            std::size_t windowSize() const noexcept { return m_windowSize; }
            void setWindowSize(std::size_t size) noexcept;

            double smoothingFactor() const noexcept { return m_smoothingFactor; }
            void setSmoothingFactor(double alpha) noexcept;

        private:
            /// Online statistics (Welford's algorithm)
            struct OnlineStats
            {
                double mean = 0.0;
                double m2 = 0.0;      // Sum of squared differences
                std::size_t count = 0;
                std::deque<double> window;  // Recent values for bounded memory
                
                void update(double value);
                double variance() const;
                double stddev() const;
            };

            /// Calculate Z-score for value against statistical model
            double calculateZScore(double value, const OnlineStats& stats) const;
            /// Calculate event rate (events per minute) using the *log timestamps*.
            double calculateEventRate(const std::string& source, Utils::TimePoint ts);


            /// Update exponentially weighted moving average
            double updateMovingAverage(double newValue, double& currentAvg, double alpha) const;

            /// Check if Z-score indicates anomaly
            bool isAnomaly(double zscore) const;

            /// Generate anomaly report from statistical deviation
            Anomaly createAnomaly(const core::LogEntry& entry, 
                                const Stats& stats, double zscore) const;

        private:
            mutable std::mutex m_mutex;

            // Per-source event rate statistics (events per minute)
            std::unordered_map<std::string, OnlineStats> m_sourceStats;
            
            // Global event statistics
            OnlineStats m_globalStats;

            // Configuration
            double m_zScoreThreshold = 3.0;       // 3-sigma rule
            std::size_t m_windowSize = 100;       // 100 events per window
            double m_smoothingFactor = 0.1;       // EWMA alpha (10% weight to new data)
            
            // Track recent timestamps for rate calculation
            std::unordered_map<std::string, std::deque<Utils::TimePoint>> m_recentBySource;

            // Rate window for per-source event-rate calculation
            Utils::seconds m_rateWindow = std::chrono::minutes(10);
        };

    } // namespace Anomaly
} // namespace LogTool
