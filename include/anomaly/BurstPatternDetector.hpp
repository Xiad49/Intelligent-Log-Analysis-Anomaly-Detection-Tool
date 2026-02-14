#pragma once

#include <deque>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

#include "core/LogEntry.hpp"
#include "core/Anomaly.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
namespace Anomaly
{
    // Detects bursty repetition of the *same* normalized message within a short time window.
    // This directly covers the "Burst pattern recognition" requirement.
    class BurstPatternDetector
    {
    public:
        struct Burst
        {
            std::string key;           // normalized signature
            std::string description;
            double score = 0.0;        // repeats per window
            core::LogLevel level = core::LogLevel::Unknown;
            std::optional<std::string> source;
            Utils::TimePoint windowStart;
            Utils::TimePoint windowEnd;
            std::vector<core::LogEntry> samples;
        };

        BurstPatternDetector();

        std::vector<Burst> processEntry(const core::LogEntry& entry);

        void reset();

        // Configuration
        Utils::seconds window() const noexcept { return m_window; }
        void setWindow(Utils::seconds w) noexcept { m_window = w; }

        std::size_t minRepeats() const noexcept { return m_minRepeats; }
        void setMinRepeats(std::size_t r) noexcept { m_minRepeats = r; }

        std::size_t maxSamples() const noexcept { return m_maxSamples; }
        void setMaxSamples(std::size_t n) noexcept { m_maxSamples = n; }

    private:
        struct State
        {
            std::deque<std::pair<Utils::TimePoint, core::LogEntry>> events;
        };

        static std::string normalizeMessage(std::string_view msg);
        static std::string signature(const core::LogEntry& e);

        void evictOld(State& st, Utils::TimePoint now) const;

    private:
        mutable std::mutex m_mutex;
        std::unordered_map<std::string, State> m_states;

        Utils::seconds m_window = std::chrono::seconds(60);
        std::size_t m_minRepeats = 20;
        std::size_t m_maxSamples = 5;
    };

} // namespace Anomaly
} // namespace LogTool
