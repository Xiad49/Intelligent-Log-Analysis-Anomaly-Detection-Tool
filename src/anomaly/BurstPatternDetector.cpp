#include "anomaly/BurstPatternDetector.hpp"

#include <cctype>
#include <regex>
#include <sstream>

#include "utils/Logger.hpp"

namespace LogTool
{
namespace Anomaly
{
    BurstPatternDetector::BurstPatternDetector()
    {
        Utils::getLogger().info("BurstPatternDetector initialized (window: 60s)");
    }

    std::string BurstPatternDetector::normalizeMessage(std::string_view msg)
    {
        // Normalize to reduce uniqueness:
        // - lower-case
        // - replace integers with <n>
        // - replace hex/uuid-like tokens with <id>
        std::string s(msg);
        for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        // Replace UUID-ish / hex-ish tokens
        // (simple heuristic, avoids pulling in a heavy tokenizer)
        static const std::regex uuidLike(R"([0-9a-f]{8,})", std::regex::icase);
        s = std::regex_replace(s, uuidLike, "<id>");

        static const std::regex numbers(R"(\b\d+\b)");
        s = std::regex_replace(s, numbers, "<n>");

        // Collapse whitespace
        std::string out;
        out.reserve(s.size());
        bool inWs = false;
        for (char c : s)
        {
            if (std::isspace(static_cast<unsigned char>(c)))
            {
                if (!inWs) out.push_back(' ');
                inWs = true;
            }
            else
            {
                out.push_back(c);
                inWs = false;
            }
        }
        // trim
        while (!out.empty() && out.front() == ' ') out.erase(out.begin());
        while (!out.empty() && out.back() == ' ') out.pop_back();
        return out;
    }

    std::string BurstPatternDetector::signature(const core::LogEntry& e)
    {
        std::ostringstream oss;
        oss << e.source().value_or("unknown") << "|" << static_cast<int>(e.level()) << "|" << normalizeMessage(e.message());
        return oss.str();
    }

    void BurstPatternDetector::evictOld(State& st, Utils::TimePoint now) const
    {
        while (!st.events.empty())
        {
            auto age = now - st.events.front().first;
            if (age <= m_window) break;
            st.events.pop_front();
        }
    }

    std::vector<BurstPatternDetector::Burst> BurstPatternDetector::processEntry(const core::LogEntry& entry)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<Burst> out;

        const auto now = entry.timestamp();
        const std::string key = signature(entry);
        auto& st = m_states[key];

        st.events.emplace_back(now, entry);
        evictOld(st, now);

        const std::size_t c = st.events.size();
        if (c >= m_minRepeats)
        {
            Burst b;
            b.key = key;
            b.level = entry.level();
            b.source = entry.source();
            b.windowStart = st.events.front().first;
            b.windowEnd = st.events.back().first;
            b.score = static_cast<double>(c);
            b.description = "Burst repetition detected: " + std::to_string(c) + " repeats within " + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(m_window).count()) + "s";
            // samples
            const std::size_t start = (c > m_maxSamples) ? (c - m_maxSamples) : 0;
            for (std::size_t i = start; i < c; ++i)
                b.samples.push_back(st.events[i].second);

            // Prevent re-emitting on every subsequent entry: keep only the most recent few
            // so we emit again if the burst continues after a cool-down.
            if (st.events.size() > m_minRepeats)
            {
                // keep last minRepeats/2 events to keep context but reduce spam
                const std::size_t keep = std::max<std::size_t>(1, m_minRepeats / 2);
                while (st.events.size() > keep) st.events.pop_front();
            }

            out.push_back(std::move(b));
        }

        return out;
    }

    void BurstPatternDetector::reset()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_states.clear();
    }

} // namespace Anomaly
} // namespace LogTool
