#include "anomaly/StatisticalDetector.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <numeric>
#include <optional>   // for std::optional
#include <string>     // for std::string

#include "utils/Logger.hpp"
#include "utils/StringUtils.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
    namespace Anomaly
    {
        using namespace core;
        using namespace Utils;

        StatisticalDetector::StatisticalDetector()
        {
            Logger& logger = getLogger();
            logger.info("StatisticalDetector initialized (Z-threshold: " +
                        std::to_string(m_zScoreThreshold) + ")");
        }

        std::vector<StatisticalDetector::Anomaly>
        StatisticalDetector::processEntry(const LogEntry& entry)
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            std::vector<Anomaly> anomalies;

            // LogEntry::source() is std::optional<std::string>
            const std::string source = entry.source().value_or("<unknown>");

            // Calculate event rate (events per minute) for this source using log timestamps
            double eventRate = calculateEventRate(source, entry.timestamp());

            // Update per-source statistics
            auto& sourceStats = m_sourceStats[source];
            sourceStats.update(eventRate);

            // Update global statistics
            m_globalStats.update(eventRate);

            // Snapshot stats for reporting
            Stats stats;
            stats.mean = sourceStats.mean;
            stats.stddev = sourceStats.stddev();
            stats.count = sourceStats.count;
            stats.lastUpdate = entry.timestamp();

            // Z-score
            const double zscore = calculateZScore(eventRate, sourceStats);
            stats.zscore = zscore;

            // Moving average: compute from the window (simple mean of stored window)
            if (!sourceStats.window.empty())
            {
                const double sum = std::accumulate(
                    sourceStats.window.begin(), sourceStats.window.end(), 0.0);
                stats.movingAverage = sum / static_cast<double>(sourceStats.window.size());
            }
            else
            {
                stats.movingAverage = eventRate;
            }

            if (isAnomaly(zscore))
            {
                anomalies.push_back(createAnomaly(entry, stats, zscore));
            }

            return anomalies;
        }

        std::optional<StatisticalDetector::Stats>
        StatisticalDetector::getStats(const std::string& source) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            auto it = m_sourceStats.find(source);
            if (it == m_sourceStats.end())
                return std::nullopt;

            const auto& onlineStats = it->second;
            Stats stats;
            stats.mean = onlineStats.mean;
            stats.stddev = onlineStats.stddev();
            stats.count = onlineStats.count;
            return stats;
        }

        std::unordered_map<std::string, StatisticalDetector::Stats>
        StatisticalDetector::getAllStats() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            std::unordered_map<std::string, Stats> result;
            for (const auto& [source, onlineStats] : m_sourceStats)
            {
                Stats stats;
                stats.mean = onlineStats.mean;
                stats.stddev = onlineStats.stddev();
                stats.count = onlineStats.count;
                result[source] = stats;
            }
            return result;
        }

        std::vector<StatisticalDetector::Anomaly>
        StatisticalDetector::detectCurrentAnomalies() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::vector<Anomaly> anomalies;
            return anomalies; // Implementation would scan current stats
        }

        void StatisticalDetector::reset()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_sourceStats.clear();
            m_globalStats = OnlineStats{};
            m_recentBySource.clear();
            getLogger().debug("StatisticalDetector reset");
        }

        void StatisticalDetector::setZScoreThreshold(double threshold) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_zScoreThreshold = std::max(1.0, threshold);
        }

        void StatisticalDetector::setWindowSize(std::size_t size) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_windowSize = std::max(static_cast<std::size_t>(10), size);

            // Note: OnlineStats::update currently uses a fixed cap (100).
            // If you want m_windowSize to actually control the window,
            // change OnlineStats::update to use m_windowSize (requires access).
        }

        void StatisticalDetector::setSmoothingFactor(double alpha) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_smoothingFactor = std::clamp(alpha, 0.01, 0.5);
        }

        // --- Online Statistics (Welford's Algorithm) ---

        void StatisticalDetector::OnlineStats::update(double value)
        {
            count++;
            double delta = value - mean;
            mean += delta / static_cast<double>(count);
            double delta2 = value - mean;
            m2 += delta * delta2;

            // Maintain sliding window
            window.push_back(value);
            if (window.size() > 100) // Fixed max window size
                window.pop_front();
        }

        double StatisticalDetector::OnlineStats::variance() const
        {
            if (count < 2) return 0.0;
            return m2 / static_cast<double>(count - 1);
        }

        double StatisticalDetector::OnlineStats::stddev() const
        {
            double var = variance();
            return var > 0.0 ? std::sqrt(var) : 0.0;
        }

        // --- Core Detection Logic ---

        double StatisticalDetector::calculateEventRate(const std::string& source, Utils::TimePoint ts)
        {
            auto& dq = m_recentBySource[source];
            dq.push_back(ts);

            // Keep only timestamps within m_rateWindow based on *log time*.
            while (!dq.empty())
            {
                auto age = ts - dq.front();
                if (age <= m_rateWindow) break;
                dq.pop_front();
            }

            if (dq.size() < 2)
                return static_cast<double>(dq.size()) * 60.0 / std::max<double>(1.0, std::chrono::duration_cast<std::chrono::seconds>(m_rateWindow).count());

            // Compute duration between first and last in minutes (avoid divide by 0)
            const double spanSec = std::max<double>(1.0, Utils::diffSeconds(dq.front(), dq.back()));
            const double spanMin = spanSec / 60.0;
            return static_cast<double>(dq.size()) / std::max(1e-6, spanMin);
        }

        double StatisticalDetector::calculateZScore(double value, const OnlineStats& stats) const
        {
            const double sd = stats.stddev();
            if (stats.count < 10 || sd == 0.0)
                return 0.0;

            return (value - stats.mean) / sd;
        }

        double StatisticalDetector::updateMovingAverage(double newValue, double& currentAvg, double alpha) const
        {
            currentAvg = alpha * newValue + (1.0 - alpha) * currentAvg;
            return currentAvg;
        }

        bool StatisticalDetector::isAnomaly(double zscore) const
        {
            return std::abs(zscore) > m_zScoreThreshold;
        }

        StatisticalDetector::Anomaly
        StatisticalDetector::createAnomaly(const LogEntry& entry,
                                          const Stats& stats,
                                          double zscore) const
        {
            const std::string source = entry.source().value_or("<unknown>");

            std::ostringstream oss;
            oss << "Statistical anomaly detected (Z=" << std::fixed << std::setprecision(2)
                << zscore << "): " << source << " event rate deviation "
                << std::abs(zscore) << "σ from mean μ=" << std::setprecision(1)
                << stats.mean << " σ=" << stats.stddev;

            Anomaly anomaly;
            anomaly.description = oss.str();
            anomaly.zscore = zscore;
            anomaly.severity = std::min(1.0, std::abs(zscore) / m_zScoreThreshold);
            anomaly.stats = stats;
            anomaly.entry = entry;

            return anomaly;
        }

    } // namespace Anomaly
} // namespace LogTool
