#include "anomaly/IpFrequencyDetector.hpp"

#include "utils/Logger.hpp"

namespace LogTool
{
namespace Anomaly
{
    IpFrequencyDetector::IpFrequencyDetector()
    {
        Utils::getLogger().info("IpFrequencyDetector initialized");
    }

    std::optional<std::string> IpFrequencyDetector::extractIp(std::string_view message)
    {
        // Very standard IPv4 regex (0-255 check is not strict; good enough for logs)
        static const std::regex ipRe(R"((\b\d{1,3}(?:\.\d{1,3}){3}\b))");
        std::cmatch m;
        if (std::regex_search(message.begin(), message.end(), m, ipRe) && m.size() >= 2)
        {
            return std::string(m[1].str());
        }
        return std::nullopt;
    }

    std::vector<IpFrequencyDetector::IpHit> IpFrequencyDetector::processEntry(const core::LogEntry& entry)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<IpHit> out;

        auto ip = extractIp(entry.message());
        if (!ip) return out;

        const std::size_t newCount = ++m_counts[*ip];
        if (newCount <= m_maxCountForRare)
        {
            // Emit only on first few occurrences so the operator sees it early.
            IpHit h;
            h.ip = *ip;
            h.count = newCount;
            h.entry = entry;
            out.push_back(std::move(h));
        }
        return out;
    }

    void IpFrequencyDetector::reset()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_counts.clear();
    }

} // namespace Anomaly
} // namespace LogTool
