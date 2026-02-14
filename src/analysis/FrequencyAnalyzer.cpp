#include "analysis/FrequencyAnalyzer.hpp"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <sstream>

#include "utils/Logger.hpp"

namespace
{
    std::string toUpperCopy(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        return s;
    }

    constexpr std::size_t kTopN = 10;
}

namespace LogTool
{
    namespace Analysis
    {
        FrequencyAnalyzer::FrequencyAnalyzer()
            : m_messageHashLength(3),
              m_spikeMultiplier(3.0),
              m_minOccurrences(2)
        {
            LogTool::Utils::getLogger().info("FrequencyAnalyzer initialized with default thresholds");
        }

        // Correct type matching header (core::LogEntry)
        void FrequencyAnalyzer::addEntry(const core::LogEntry &entry)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            updateUnlocked(entry);
        }

        FrequencyAnalyzer::FrequencyStats FrequencyAnalyzer::getStats() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            FrequencyStats stats{};

            // Total events = sum of source counts
            std::size_t total = 0;
            for (const auto &kv : m_sourceCounts)
                total += kv.second;

            stats.totalEvents = total;
            stats.bySource = m_sourceCounts;
            stats.byLevel  = m_levelCounts;
            stats.topMessages = m_messageCounts;

            // Top sources
            stats.topSources.clear();
            stats.topSources.reserve(std::min<std::size_t>(kTopN, m_sourceCounts.size()));

            for (const auto &kv : m_sourceCounts)
            {
                if (kv.second > 0)
                    stats.topSources.emplace_back(kv.first, kv.second);
            }

            std::sort(stats.topSources.begin(), stats.topSources.end(),
                      [](const auto &a, const auto &b) { return a.second > b.second; });

            if (stats.topSources.size() > kTopN)
                stats.topSources.resize(kTopN);

            // Top message hashes
            stats.topMessagesSorted.clear();
            stats.topMessagesSorted.reserve(std::min<std::size_t>(kTopN, m_messageCounts.size()));

            for (const auto &kv : m_messageCounts)
            {
                if (kv.second > 0)
                    stats.topMessagesSorted.emplace_back(kv.first, kv.second);
            }

            std::sort(stats.topMessagesSorted.begin(), stats.topMessagesSorted.end(),
                      [](const auto &a, const auto &b) { return a.second > b.second; });

            if (stats.topMessagesSorted.size() > kTopN)
                stats.topMessagesSorted.resize(kTopN);

            return stats;
        }

        std::vector<std::string> FrequencyAnalyzer::detectAnomalies() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::vector<std::string> anomalies;

            // Source spikes
            for (const auto &kv : m_sourceCounts)
            {
                const std::string &source = kv.first;
                const std::size_t count = kv.second;

                auto avgIt = m_sourceMovingAvg.find(source);
                if (avgIt != m_sourceMovingAvg.end() && avgIt->second > 0.0)
                {
                    if (static_cast<double>(count) > avgIt->second * m_spikeMultiplier)
                    {
                        std::ostringstream oss;
                        oss << "Source '" << source << "' spike: " << count
                            << " events (" << (static_cast<double>(count) / avgIt->second) << "x average)";
                        anomalies.push_back(oss.str());
                    }
                }
            }

            // Rare message hashes
            for (const auto &kv : m_messageCounts)
            {
                const std::string &msgHash = kv.first;
                const std::size_t count = kv.second;

                if (count < m_minOccurrences)
                {
                    std::ostringstream oss;
                    oss << "Rare message pattern '" << msgHash << "': only " << count << " occurrences";
                    anomalies.push_back(oss.str());
                }
            }

            return anomalies;
        }

        void FrequencyAnalyzer::reset()
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            m_sourceCounts.clear();
            m_levelCounts.clear();
            m_messageCounts.clear();
            m_sourceHistory.clear();
            m_sourceMovingAvg.clear();

            LogTool::Utils::getLogger().debug("FrequencyAnalyzer counters reset");
        }

        void FrequencyAnalyzer::setMessageHashLength(std::size_t length) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_messageHashLength = length;
        }

        void FrequencyAnalyzer::setSpikeMultiplier(double multiplier) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_spikeMultiplier = multiplier;
        }

        void FrequencyAnalyzer::setMinOccurrences(std::size_t count) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_minOccurrences = count;
        }

        std::string FrequencyAnalyzer::hashMessage(const std::string &message) const
        {
            std::istringstream iss(message);
            std::vector<std::string> words;
            std::string word;

            while (words.size() < m_messageHashLength && (iss >> word))
                words.push_back(toUpperCopy(word));

            if (words.empty())
                return "EMPTY";

            std::ostringstream oss;
            std::copy(words.begin(), words.end(), std::ostream_iterator<std::string>(oss, " "));
            std::string result = oss.str();
            if (!result.empty())
                result.pop_back(); // remove trailing space
            return result;
        }

        // Correct type matching header (core::LogEntry)
        void FrequencyAnalyzer::updateUnlocked(const core::LogEntry &entry)
        {
            // Unwrap `std::optional<std::string>` using `.value()` for source
            m_sourceCounts[entry.source().value_or("")]++;  // Safe unwrap
            m_levelCounts[entry.level()]++;

            const std::string msgHash = hashMessage(entry.message());
            m_messageCounts[msgHash]++;

            updateMovingAverage(entry.source().value_or(""));  // Safe unwrap
        }

        void FrequencyAnalyzer::updateMovingAverage(const std::string &source)
        {
            auto &history = m_sourceHistory[source];
            history.push_back(m_sourceCounts[source]);

            // Keep only last 10 samples
            if (history.size() > 10)
                history.erase(history.begin());

            double sum = 0.0;
            for (std::size_t v : history)
                sum += static_cast<double>(v);

            m_sourceMovingAvg[source] =
                history.empty() ? 0.0 : (sum / static_cast<double>(history.size()));
        }

    } // namespace Analysis
} // namespace LogTool
