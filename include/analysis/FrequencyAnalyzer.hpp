#pragma once

#include <cstddef>
#include <mutex>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/LogEntry.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
    namespace Analysis
    {
        // Hash functor for core::LogLevel (for unordered_map with enum class)
        struct LogLevelHash
        {
            std::size_t operator()(core::LogLevel lvl) const noexcept
            {
                using U = std::underlying_type_t<core::LogLevel>;
                return std::hash<U>{}(static_cast<U>(lvl));
            }
        };

        class FrequencyAnalyzer
        {
        public:
            struct FrequencyStats
            {
                std::size_t totalEvents = 0;

                std::unordered_map<std::string, std::size_t> bySource;
                std::unordered_map<core::LogLevel, std::size_t, LogLevelHash> byLevel;
                std::unordered_map<std::string, std::size_t> topMessages;
                std::vector<std::pair<std::string, std::size_t>> topSources;
                std::vector<std::pair<std::string, std::size_t>> topMessagesSorted;
            };

            FrequencyAnalyzer();

            FrequencyAnalyzer(const FrequencyAnalyzer &)            = delete;
            FrequencyAnalyzer &operator=(const FrequencyAnalyzer &) = delete;
            FrequencyAnalyzer(FrequencyAnalyzer &&)                 = delete;
            FrequencyAnalyzer &operator=(FrequencyAnalyzer &&)      = delete;

            // Correct type: core::LogEntry
            void addEntry(const core::LogEntry &entry);

            FrequencyStats getStats() const;
            std::vector<std::string> detectAnomalies() const;

            void reset();

            std::size_t messageHashLength() const noexcept { return m_messageHashLength; }
            void setMessageHashLength(std::size_t length) noexcept;

            double spikeMultiplier() const noexcept { return m_spikeMultiplier; }
            void setSpikeMultiplier(double multiplier) noexcept;

            std::size_t minOccurrences() const noexcept { return m_minOccurrences; }
            void setMinOccurrences(std::size_t count) noexcept;

        private:
            std::string hashMessage(const std::string &message) const;

            // Correct type: core::LogEntry
            void updateUnlocked(const core::LogEntry &entry);

            void updateMovingAverage(const std::string &source);

        private:
            mutable std::mutex m_mutex;

            std::unordered_map<std::string, std::size_t> m_sourceCounts;
            std::unordered_map<core::LogLevel, std::size_t, LogLevelHash> m_levelCounts;
            std::unordered_map<std::string, std::size_t> m_messageCounts;

            std::unordered_map<std::string, std::vector<std::size_t>> m_sourceHistory;
            std::unordered_map<std::string, double> m_sourceMovingAvg;

            std::size_t m_messageHashLength = 3;
            double m_spikeMultiplier = 3.0;
            std::size_t m_minOccurrences = 2;
        };

    } // namespace Analysis
} // namespace LogTool
