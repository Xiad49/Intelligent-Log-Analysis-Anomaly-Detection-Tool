#include "anomaly/SpikeDetector.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include "utils/Logger.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
    namespace Anomaly
    {
        using namespace core;
        using namespace Utils;

        SpikeDetector::SpikeDetector()
        {
            Logger& logger = getLogger();
            logger.info("SpikeDetector initialized (threshold: " + 
                       std::to_string(m_spikeThreshold) + "x, short: " + 
                       std::to_string(m_shortWindow.count()) + "s)");
        }

        std::vector<SpikeDetector::SpikeAnomaly> SpikeDetector::processEntry(const LogEntry& entry)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            std::vector<SpikeAnomaly> anomalies;
            auto nowTime = entry.timestamp();
            
            // Get or create source state
            const auto srcOpt = entry.source();
            if (!srcOpt || srcOpt->empty())
            {
                // No source -> can't track per-source spikes
                return {};
            }

            const std::string& src = *srcOpt;
            auto& state = m_sourceStates[src];

            
            // Advance windows based on current timestamp
            advanceWindows(state, nowTime);
            
            // Add to current (short) window
            state.recentEvents.push_back(nowTime);
            state.currentCount++;
            
            // Add to baseline window
            state.baselineEvents.push_back(nowTime);
            state.baselineCount++;
            
            // Evict old events from windows
            while (!state.recentEvents.empty() && 
                   Utils::diffSeconds(state.recentEvents.front(), nowTime) > m_shortWindow.count())
            {
                state.recentEvents.pop_front();
                state.currentCount--;
            }
            
            while (!state.baselineEvents.empty() && 
                   Utils::diffSeconds(state.baselineEvents.front(), nowTime) > m_baselineWindow.count())
            {
                state.baselineEvents.pop_front();
                state.baselineCount--;
            }
            
            // Store sample event (bounded)
            state.samples.push_back(entry);
            if (state.samples.size() > m_maxSampleEvents)
            {
                state.samples.erase(state.samples.begin());
            }
            
            // Check for spike
            SpikeStats stats = calculateStats(state, src, nowTime);
            if (isSpike(stats))
            {
                auto anomaly = createAnomaly(stats, state.samples);
                anomalies.push_back(anomaly);
            }
            
            return anomalies;
        }

        std::optional<SpikeDetector::SpikeStats> SpikeDetector::getStats(const std::string& source) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_sourceStates.find(source);
            if (it == m_sourceStates.end())
                return std::nullopt;
                
            return calculateStats(it->second, source, now());
        }

        std::vector<SpikeDetector::SpikeAnomaly> SpikeDetector::checkAllSpikes() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::vector<SpikeAnomaly> anomalies;
            auto nowTime = now();
            
            for (const auto& [source, state] : m_sourceStates)
            {
                SpikeStats stats = calculateStats(state, source, nowTime);
                if (isSpike(stats))
                {
                    SpikeAnomaly anomaly;
                    anomaly.description = "Active spike detected";
                    anomaly.severity = std::min(1.0, (stats.spikeRatio - 1.0) / (m_spikeThreshold - 1.0));
                    anomaly.stats = stats;
                    anomalies.push_back(anomaly);
                }
            }
            
            return anomalies;
        }

        void SpikeDetector::reset()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_sourceStates.clear();
            getLogger().debug("SpikeDetector reset");
        }

        void SpikeDetector::setSpikeThreshold(double ratio) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_spikeThreshold = std::max(1.1, ratio);
        }

        void SpikeDetector::setShortWindow(seconds duration) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_shortWindow = duration;
        }

        void SpikeDetector::setBaselineWindow(seconds duration) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_baselineWindow = duration;
        }

        void SpikeDetector::setMaxSampleEvents(std::size_t count) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_maxSampleEvents = std::max(static_cast<std::size_t>(1), count);
        }

        // --- Private Implementation ---

        void SpikeDetector::advanceWindows(SourceState& state, TimePoint now)
        {
            // Simple time-based window advancement
            // Windows auto-adjust based on event timestamps
        }

        SpikeDetector::SpikeStats SpikeDetector::calculateStats(const SourceState& state, 
                                                              const std::string& source,
                                                              TimePoint now) const
        {
            SpikeStats stats;
            stats.source = source;
            stats.currentCount = state.currentCount;
            stats.baselineCount = state.baselineCount ? state.baselineCount : 1;
            stats.windowStart = now - m_shortWindow;
            stats.windowEnd = now;
            
            // Spike ratio: current rate vs baseline rate
            double currentRate = static_cast<double>(state.currentCount) / m_shortWindow.count();
            double baselineRate = static_cast<double>(state.baselineCount) / m_baselineWindow.count();
            stats.spikeRatio = baselineRate > 0 ? currentRate / baselineRate : 1.0;
            
            // Rate of change from previous window
            if (state.previousCount > 0)
            {
                stats.rateOfChange = static_cast<double>(state.currentCount - state.previousCount) / 
                                   static_cast<double>(state.previousCount);
            }
            
            return stats;
        }

        bool SpikeDetector::isSpike(const SpikeStats& stats) const
        {
            // Spike conditions:
            // 1. Current exceeds threshold multiple of baseline
            // 2. Minimum events in current window
            // 3. Reasonable baseline established
            return stats.spikeRatio > m_spikeThreshold &&
                   stats.currentCount >= 5 &&
                   stats.baselineCount >= 10;
        }

        SpikeDetector::SpikeAnomaly SpikeDetector::createAnomaly(const SpikeStats& stats, 
                                                               const std::vector<LogEntry>& samples) const
        {
            std::ostringstream oss;
            oss << "Spike detected: " << stats.source << " (" 
                << stats.currentCount << " events in " << m_shortWindow.count() 
                << "s, " << std::fixed << std::setprecision(1)
                << stats.spikeRatio << "x baseline, ROC=" 
                << std::setprecision(2) << stats.rateOfChange;
                
            SpikeAnomaly anomaly;
            anomaly.description = oss.str();
            anomaly.severity = std::min(1.0, (stats.spikeRatio - 1.0) / (m_spikeThreshold - 1.0));
            anomaly.stats = stats;
            anomaly.sampleEvents = samples;
            
            return anomaly;
        }

    } // namespace Anomaly
} // namespace LogTool
