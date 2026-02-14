#pragma once

#include <regex>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <optional>

#include "core/LogEntry.hpp"

namespace LogTool
{
namespace Anomaly
{
    // Extracts IPv4 addresses from messages and flags rare IPs.
    // Covers the "Rare IP detection" requirement even though core::LogEntry does not have a dedicated IP field.
    class IpFrequencyDetector
    {
    public:
        struct IpHit
        {
            std::string ip;
            std::size_t count = 0;
            core::LogEntry entry;
        };

        IpFrequencyDetector();

        // Returns IpHit anomalies when an IP is considered rare under the current definition.
        std::vector<IpHit> processEntry(const core::LogEntry& entry);

        void reset();

        // Configuration
        // "Rare" is defined as count <= maxCount (default 5). For large datasets, consider raising this.
        std::size_t maxCountForRare() const noexcept { return m_maxCountForRare; }
        void setMaxCountForRare(std::size_t v) noexcept { m_maxCountForRare = v; }

    private:
        static std::optional<std::string> extractIp(std::string_view message);

    private:
        mutable std::mutex m_mutex;
        std::unordered_map<std::string, std::size_t> m_counts;
        std::size_t m_maxCountForRare = 5;
    };

} // namespace Anomaly
} // namespace LogTool
