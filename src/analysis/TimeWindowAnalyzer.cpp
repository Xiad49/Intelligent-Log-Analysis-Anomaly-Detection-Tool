#include "analysis/TimeWindowAnalyzer.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>  // Include for std::setprecision
#include "utils/Logger.hpp"

namespace LogTool
{
    namespace Analysis
    {
        using namespace core;  // Correct namespace usage for core::LogEntry and core::LogLevel
        using namespace Utils;

        TimeWindowAnalyzer::TimeWindowAnalyzer()
        {
            // Window bounds will be aligned to the first log entry timestamp.
            m_currentWindow.start = Utils::TimePoint{};
            m_currentWindow.end = Utils::TimePoint{};
            m_initialized = false;
            
            Logger& logger = getLogger();
            logger.info("TimeWindowAnalyzer initialized (window: " + 
                       std::to_string(m_windowSize.count()) + "s)");
        }

        void TimeWindowAnalyzer::addEntry(const core::LogEntry& entry)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            addEventUnlocked(entry);
        }

        TimeWindowAnalyzer::WindowStats TimeWindowAnalyzer::currentWindowStats() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return calculateStats(m_currentWindow);
        }

        std::vector<TimeWindowAnalyzer::Anomaly> TimeWindowAnalyzer::detectAnomalies() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::vector<Anomaly> anomalies;

            // Check current window
            auto currentAnomaly = checkErrorSpike(m_currentWindow);
            if (currentAnomaly.score > 0.0)
                anomalies.push_back(currentAnomaly);

            currentAnomaly = checkBurst(m_currentWindow);
            if (currentAnomaly.score > 0.0)
                anomalies.push_back(currentAnomaly);

            // Check recent history windows
            for (const auto& window : m_windowHistory)
            {
                auto histAnomaly = checkErrorSpike(window);
                if (histAnomaly.score > 0.0)
                    anomalies.push_back(histAnomaly);

                histAnomaly = checkBurst(window);
                if (histAnomaly.score > 0.0)
                    anomalies.push_back(histAnomaly);
            }

            // Check for silence between windows
            if (!m_windowHistory.empty())
            {
                auto silence = checkSilence(m_currentWindow);
                if (silence.score > 0.0)
                    anomalies.push_back(silence);
            }

            return anomalies;
        }

        void TimeWindowAnalyzer::advanceWindow(seconds windowSize)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            // Legacy manual advance kept for API compatibility.
            // When used, it advances relative to the current window end.
            if (!m_initialized)
            {
                // Nothing to do without a base timestamp.
                return;
            }

            // Save current window to history (if not empty)
            if (!m_currentWindow.events.empty())
            {
                m_windowHistory.push_back(m_currentWindow);
                if (m_windowHistory.size() > m_maxHistoryWindows)
                    m_windowHistory.pop_front();
            }

            m_currentWindow.start = m_currentWindow.end;
            m_currentWindow.end = m_currentWindow.start + windowSize;
            m_currentWindow.events.clear();
            m_currentWindow.sourceCounts.clear();
        }

        void TimeWindowAnalyzer::reset()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_currentWindow = TimeBucket{};
            m_currentWindow.start = Utils::TimePoint{};
            m_currentWindow.end = Utils::TimePoint{};
            m_initialized = false;
            m_windowHistory.clear();
            
            getLogger().debug("TimeWindowAnalyzer reset");
        }

        void TimeWindowAnalyzer::setWindowSize(seconds size) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_windowSize = size;
            // If already initialized, keep current start and recompute end.
            if (m_initialized)
            {
                m_currentWindow.end = m_currentWindow.start + m_windowSize;
            }
        }

        void TimeWindowAnalyzer::setErrorRateThreshold(double threshold) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_errorRateThreshold = threshold;
        }

        void TimeWindowAnalyzer::setBurstThreshold(std::size_t count) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_burstThreshold = count;
        }

        void TimeWindowAnalyzer::setSilenceThreshold(seconds duration) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_silenceThreshold = duration;
        }

        // --- Private implementation ---

        void TimeWindowAnalyzer::addEventUnlocked(const core::LogEntry& entry)
        {
            const auto ts = entry.timestamp();

            // Initialize window to the first event timestamp
            if (!m_initialized)
            {
                m_currentWindow.start = ts;
                m_currentWindow.end = m_currentWindow.start + m_windowSize;
                m_initialized = true;
            }

            // Advance windows forward until the timestamp fits
            while (ts >= m_currentWindow.end)
            {
                // Save current window (even if empty) to preserve gaps for silence detection
                m_windowHistory.push_back(m_currentWindow);
                if (m_windowHistory.size() > m_maxHistoryWindows)
                    m_windowHistory.pop_front();

                m_currentWindow.start = m_currentWindow.end;
                m_currentWindow.end = m_currentWindow.start + m_windowSize;
                m_currentWindow.events.clear();
                m_currentWindow.sourceCounts.clear();
            }

            // Drop events that are too far in the past relative to current window
            if (ts < m_currentWindow.start)
                return;

            TimedEvent timedEvent{
                .timestamp = entry.timestamp(),
                .level = entry.level(),
                .source = entry.source().value_or("") // Access source safely (default to empty string)
            };

            // Add to events deque (oldest first)
            m_currentWindow.events.push_back(timedEvent);
            m_currentWindow.sourceCounts[entry.source().value_or("")]++; // Increment source count

            // Evict old events (keep deque bounded)
            evictOldEvents(m_currentWindow);
        }

        void TimeWindowAnalyzer::evictOldEvents(TimeBucket& bucket)
        {
            while (!bucket.events.empty() && 
                   bucket.events.front().timestamp < bucket.start)
            {
                const auto& oldEvent = bucket.events.front();
                bucket.sourceCounts[oldEvent.source]--;
                if (bucket.sourceCounts[oldEvent.source] == 0)
                {
                    bucket.sourceCounts.erase(oldEvent.source);
                }
                bucket.events.pop_front();
            }
        }

        TimeWindowAnalyzer::WindowStats TimeWindowAnalyzer::calculateStats(const TimeBucket& bucket) const
        {
            WindowStats stats;
            stats.windowStart = bucket.start;
            stats.windowEnd = bucket.end;
            stats.totalEvents = bucket.events.size();

            std::size_t errorCount = 0;
            for (const auto& event : bucket.events)
            {
                if (event.level == core::LogLevel::Error || event.level == core::LogLevel::Critical)
                {
                    errorCount++;
                }
            }
            
            stats.errorEvents = errorCount;
            stats.errorRate = stats.totalEvents > 0 ? 
                static_cast<double>(errorCount) / stats.totalEvents : 0.0;
            stats.eventsBySource = bucket.sourceCounts;

            return stats;
        }

        TimeWindowAnalyzer::Anomaly TimeWindowAnalyzer::checkErrorSpike(const TimeBucket& bucket) const
        {
            auto stats = calculateStats(bucket);
            Anomaly anomaly;
            
            if (stats.errorRate > m_errorRateThreshold)
            {
                anomaly.score = std::min(1.0, stats.errorRate * 2.0);
                std::ostringstream oss;
                oss << "Error spike: " << std::fixed << std::setprecision(1)
                    << stats.errorRate * 100 << "% errors in [" 
                    << formatTimestamp(stats.windowStart, "%H:%M:%S") << "-"
                    << formatTimestamp(stats.windowEnd, "%H:%M:%S") << "]";
                anomaly.description = oss.str();
                anomaly.stats = stats;
            }
            
            return anomaly;
        }

        TimeWindowAnalyzer::Anomaly TimeWindowAnalyzer::checkBurst(const TimeBucket& bucket) const
        {
            auto stats = calculateStats(bucket);
            Anomaly anomaly;
            
            if (stats.totalEvents > m_burstThreshold)
            {
                anomaly.score = std::min(1.0, static_cast<double>(stats.totalEvents) / m_burstThreshold);
                std::ostringstream oss;
                oss << "Event burst: " << stats.totalEvents 
                    << " events in " << m_windowSize.count() << "s window";
                anomaly.description = oss.str();
                anomaly.stats = stats;
            }
            
            return anomaly;
        }

        TimeWindowAnalyzer::Anomaly TimeWindowAnalyzer::checkSilence(const TimeBucket& bucket) const
        {
            Anomaly anomaly;
            
            // Check gap between this window and previous
            if (!m_windowHistory.empty())
            {
                auto prevEnd = m_windowHistory.back().end;
                auto gap = Utils::diffSeconds(prevEnd, bucket.start);
                
                if (gap > static_cast<std::int64_t>(m_silenceThreshold.count()))
                {
                    anomaly.score = std::min(1.0, static_cast<double>(gap) / m_silenceThreshold.count());
                    std::ostringstream oss;
                    oss << "Silence detected: " << gap << "s gap since last activity";
                    anomaly.description = oss.str();
                }
            }
            
            return anomaly;
        }

    } // namespace Analysis
} // namespace LogTool
