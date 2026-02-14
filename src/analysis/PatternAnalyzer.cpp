#include "analysis/PatternAnalyzer.hpp"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include "utils/Logger.hpp"
#include "utils/StringUtils.hpp"

namespace LogTool
{
    namespace Analysis
    {
        using namespace core;  // Correct usage of 'core' namespace
        using namespace Utils;

        // EventSignature hash and equality
        bool PatternAnalyzer::EventSignature::operator==(const EventSignature& other) const
        {
            return source == other.source &&
                   level == other.level &&
                   messagePrefix == other.messagePrefix;
        }

        struct PatternAnalyzer::EventSignature::Hash 
        {
            std::size_t operator()(const EventSignature& sig) const noexcept
            {
                std::size_t h1 = std::hash<std::string>{}(sig.source);
                std::size_t h2 = std::hash<int>{}(static_cast<int>(sig.level));
                std::size_t h3 = std::hash<std::string>{}(sig.messagePrefix);
                return h1 ^ (h2 << 1) ^ h3;
            }
        };

        PatternAnalyzer::PatternAnalyzer()
        {
            Logger& logger = getLogger();
            logger.info("PatternAnalyzer initialized (window: " +
                       std::to_string(m_sequenceWindowSize) + " events)");
        }

        void PatternAnalyzer::addEntry(const core::LogEntry& entry)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            // Add to recent events window
            m_recentEvents.push_back(entry);
            
            // Evict old events to maintain window size
            if (m_recentEvents.size() > m_sequenceWindowSize)
            {
                m_recentEvents.pop_front();
            }
            
            // Extract all possible sequences (n-grams) from recent events
            for (std::size_t len = 2; len <= std::min(m_sequenceWindowSize, m_recentEvents.size()); ++len)
            {
                for (std::size_t start = 0; start <= m_recentEvents.size() - len; ++start)
                {
                    EventSequence sequence;
                    sequence.reserve(len);
                    
                    for (std::size_t i = start; i < start + len; ++i)
                    {
                        sequence.push_back(createSignature(m_recentEvents[i]));
                    }
                    
                    std::string sig = sequenceToSignature(sequence);
                    updatePatternUnlocked(sequence, m_recentEvents.back());
                }
            }
        }

        PatternAnalyzer::PatternStats PatternAnalyzer::getStats() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            PatternStats stats;
            stats.totalPatterns = m_patterns.size();

            // Count repeating patterns (freq >= 2)
            for (const auto& [sig, pattern] : m_patterns)
            {
                if (pattern.frequency >= 2)
                    stats.repeatingPatterns++;

                // Count error chains
                if (isErrorChainFromSignature(sig))
                    stats.errorChains++;
            }

            // Top patterns by frequency
            stats.topPatterns.clear(); // Clear before adding top patterns

            // Sort patterns by frequency
            std::vector<std::pair<std::string, std::size_t>> sortedPatterns;
            for (const auto& [sig, pattern] : m_patterns) {
                sortedPatterns.push_back({sig, pattern.frequency});
            }

            std::sort(sortedPatterns.begin(), sortedPatterns.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });

            // Keep only top 10 patterns
            if (sortedPatterns.size() > 10)
                sortedPatterns.resize(10);

            // Dynamically insert top patterns (frequency, or other relevant data)
            stats.topPatterns.clear(); // Ensure it's cleared before adding new ones
            for (const auto& item : sortedPatterns)
            {
                // Insert pattern frequency into topPatterns
                stats.topPatterns[item.first] = item.second;  
            }

            return stats;
        }

        std::vector<std::string> PatternAnalyzer::detectAnomalies() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::vector<std::string> anomalies;
            
            // Check for novel high-severity patterns (first time seen)
            for (const auto& [sig, pattern] : m_patterns)
            {
                if (pattern.frequency == 1 && isHighSeverityPattern(sig))
                {
                    std::ostringstream oss;
                    oss << "Novel high-severity pattern: " << sig.substr(0, 50) << "...";
                    anomalies.push_back(oss.str());
                }
            }
            
            // Check for unusual sequence transitions
            for (const auto& [sig, count] : m_sequenceCounts)
            {
                if (count == 1) // Never seen before
                {
                    anomalies.push_back("New sequence pattern: " + sig);
                }
            }
            
            return anomalies;
        }

        void PatternAnalyzer::reset()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_recentEvents.clear();
            m_patterns.clear();
            m_sequenceCounts.clear();
            getLogger().debug("PatternAnalyzer reset");
        }

        void PatternAnalyzer::setSequenceWindowSize(std::size_t size) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_sequenceWindowSize = size;
        }

        void PatternAnalyzer::setMaxPatternExamples(std::size_t count) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_maxPatternExamples = count;
        }

        void PatternAnalyzer::setPatternTimeout(Utils::seconds timeout) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_patternTimeout = timeout;
        }

        // --- Private implementation ---

        PatternAnalyzer::EventSignature PatternAnalyzer::createSignature(const core::LogEntry& entry) const
        {
            EventSignature sig;
            sig.source = entry.source().value_or("");  // Handle optional source
            sig.level = entry.level();
            
            // Take first 3 words of message as prefix (using StringUtils)
            auto words = Utils::splitAndTrim(entry.message(), ' ');
            std::ostringstream oss;
            for (std::size_t i = 0; i < std::min<std::size_t>(3, words.size()); ++i)
            {
                if (i > 0) oss << " ";
                oss << words[i];
            }
            sig.messagePrefix = oss.str();
            
            return sig;
        }

        std::string PatternAnalyzer::sequenceToSignature(const EventSequence& sequence) const
        {
            std::ostringstream oss;
            for (std::size_t i = 0; i < sequence.size(); ++i)
            {
                if (i > 0) oss << "->";
                oss << sequence[i].source << ":" 
                    << static_cast<int>(sequence[i].level) << ":" 
                    << sequence[i].messagePrefix.substr(0, 20);
            }
            return oss.str();
        }

        void PatternAnalyzer::updatePatternUnlocked(const EventSequence& sequence, 
                                                  const core::LogEntry& latestEntry)
        {
            std::string sig = sequenceToSignature(sequence);
            
            // Update sequence count
            m_sequenceCounts[sig]++;
            
            // Update pattern tracking
            auto& pattern = m_patterns[sig];
            pattern.signature = sig;
            pattern.frequency++;
            pattern.lastSeen = latestEntry.timestamp();
            
            if (pattern.firstSeen == TimePoint{})
            {
                pattern.firstSeen = latestEntry.timestamp();
            }
            
            // Keep only recent examples
            pattern.examples.push_back(latestEntry);
            if (pattern.examples.size() > m_maxPatternExamples)
            {
                pattern.examples.erase(pattern.examples.begin());
            }
        }

        bool PatternAnalyzer::isErrorChain(const EventSequence& sequence) const
        {
            // Error chain: 3+ consecutive ERROR/CRITICAL events
            if (sequence.size() < 3) return false;
            
            std::size_t errorCount = 0;
            for (const auto& sig : sequence)
            {
                if (sig.level == core::LogLevel::Error || sig.level == core::LogLevel::Critical)
                {
                    errorCount++;
                }
            }
            return errorCount >= 3;
        }

        bool PatternAnalyzer::isErrorChainFromSignature(const std::string& sig) const
        {
            // Quick check based on signature content
            return sig.find("ERROR") != std::string::npos || 
                   sig.find("CRITICAL") != std::string::npos;
        }

        bool PatternAnalyzer::isHighSeverityPattern(const std::string& sig) const
        {
            return sig.find("ERROR") != std::string::npos || 
                   sig.find("CRITICAL") != std::string::npos ||
                   sig.find("FATAL") != std::string::npos;
        }

    } // namespace Analysis
} // namespace LogTool
