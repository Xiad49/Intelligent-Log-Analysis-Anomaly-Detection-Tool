#include "report/JsonReporter.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

#include "utils/Logger.hpp"
#include "utils/StringUtils.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
namespace Report
{
    JsonReporter::JsonReporter(PrettyPrint pretty)
        : m_prettyPrint(pretty),
          m_maxAnomalies(100),
          m_includeSamples(true),
          m_minSeverity(0.0)
    {
        Utils::getLogger().debug(
            "JsonReporter initialized (pretty: " +
            std::to_string(static_cast<int>(pretty)) + ")");
    }

    void JsonReporter::generateReport(const core::Report& report)
    {
        // Keep a copy of the report metadata (time range, counters, etc.)
        m_report = report;

        // Filter anomalies (do NOT mutate core::Report in case it is shared elsewhere)
        m_anomalies.clear();
        m_anomalies.reserve(report.anomalies().size());

        for (const auto& a : report.anomalies())
        {
            // core::Anomaly::severity() is an enum (0..N). We map the user threshold (0..1)
            // into that same enum range in a stable way.
            // Common ranges: 0..4. If the enum is larger, this still behaves reasonably.
            const int sev = static_cast<int>(a.severity());
            const int maxSev = 4;
            const double sevNorm = (maxSev <= 0) ? 0.0 : std::clamp(static_cast<double>(sev) / maxSev, 0.0, 1.0);

            if (sevNorm + 1e-12 >= m_minSeverity)
                m_anomalies.push_back(a);
        }

        // Sort anomalies by (severity desc, score desc, recency desc)
        std::sort(m_anomalies.begin(), m_anomalies.end(),
                  [](const core::Anomaly& a, const core::Anomaly& b) {
                      if (a.severity() != b.severity())
                          return static_cast<int>(a.severity()) > static_cast<int>(b.severity());
                      if (a.score() != b.score())
                          return a.score() > b.score();
                      if (a.windowEnd() != b.windowEnd())
                          return a.windowEnd() > b.windowEnd();
                      return a.description() < b.description();
                  });

        if (m_maxAnomalies > 0 && m_anomalies.size() > m_maxAnomalies)
            m_anomalies.resize(m_maxAnomalies);

        Utils::getLogger().debug(
            "Json report prepared: " + std::to_string(m_anomalies.size()) + " anomalies");
    }

    void JsonReporter::writeJson(std::ostream& output) const
    {
        if (m_prettyPrint == PrettyPrint::PRETTY)
            writePrettyJson(output);
        else
            writeCompactJson(output);
    }

    std::string JsonReporter::getJsonString() const
    {
        std::ostringstream oss;
        writeJson(oss);
        return oss.str();
    }

    std::string JsonReporter::anomalyToJson(const core::Anomaly& a) const
    {
        std::ostringstream oss;
        oss << "{";
        oss << "\"type\":" << static_cast<int>(a.type()) << ",";
        oss << "\"severity\":" << static_cast<int>(a.severity()) << ",";
        oss << "\"score\":" << std::fixed << std::setprecision(6) << a.score() << ",";
        oss << "\"windowStart\":\"" << formatIsoTimestamp(a.windowStart()) << "\",";
        oss << "\"windowEnd\":\"" << formatIsoTimestamp(a.windowEnd()) << "\",";
        oss << "\"source\":\"" << escapeJsonString(a.source().value_or("")) << "\",";
        oss << "\"description\":\"" << escapeJsonString(a.description()) << "\"";

        // Optional sample payloads are not part of the current core::Anomaly API.
        // Keep this hook for future expansion.
        (void)m_includeSamples;

        oss << "}";
        return oss.str();
    }

    std::string JsonReporter::summaryToJson(const core::Report& report) const
    {
        std::ostringstream oss;
        oss << "{";
        oss << "\"analysisStart\":\"" << formatIsoTimestamp(report.analysisStart()) << "\",";
        oss << "\"analysisEnd\":\"" << formatIsoTimestamp(report.analysisEnd()) << "\",";
        oss << "\"totalEvents\":" << report.totalEntries() << ",";
        oss << "\"totalErrors\":" << report.totalErrorEvents() << ",";
        oss << "\"totalWarnings\":" << report.totalWarningEvents();
        oss << "}";
        return oss.str();
    }

    void JsonReporter::setPrettyPrint(PrettyPrint mode) noexcept
    {
        m_prettyPrint = mode;
    }

    void JsonReporter::setMaxAnomalies(std::size_t count) noexcept
    {
        m_maxAnomalies = count;
    }

    void JsonReporter::setIncludeSamples(bool include) noexcept
    {
        m_includeSamples = include;
    }

    void JsonReporter::setFilterSeverity(double minSeverity) noexcept
    {
        m_minSeverity = std::clamp(minSeverity, 0.0, 1.0);
    }

    // ---- Private helpers ----

    std::string JsonReporter::escapeJsonString(const std::string& str)
    {
        std::string result;
        result.reserve(str.size() + 8);

        for (unsigned char uc : str)
        {
            const char c = static_cast<char>(uc);
            switch (c)
            {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default:
                    if (uc < 0x20)
                    {
                        result += "\\u";
                        result += toHex(static_cast<unsigned int>(uc), 4);
                    }
                    else
                    {
                        result += c;
                    }
                    break;
            }
        }
        return result;
    }

    std::string JsonReporter::formatIsoTimestamp(Utils::TimePoint tp)
    {
        return Utils::toIso8601(tp);
    }

    std::string JsonReporter::toHex(unsigned int value, std::size_t width)
    {
        std::ostringstream oss;
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(static_cast<int>(width))
            << value;
        return oss.str();
    }

    void JsonReporter::writeCompactJson(std::ostream& output) const
    {
        output << "{";

        // Summary
        output << "\"generated\":\"" << formatIsoTimestamp(Utils::now()) << "\",";
        output << "\"summary\":" << summaryToJson(m_report) << ",";

        // Optional processed file
        output << "\"processedFile\":";
        if (m_report.processedFile().has_value())
            output << "\"" << escapeJsonString(*m_report.processedFile()) << "\"";
        else
            output << "null";
        output << ",";

        // Anomalies
        output << "\"anomalyCount\":" << m_anomalies.size() << ",";
        output << "\"anomalies\":[";
        for (std::size_t i = 0; i < m_anomalies.size(); ++i)
        {
            if (i) output << ",";
            output << anomalyToJson(m_anomalies[i]);
        }
        output << "]";

        output << "}";
    }

    void JsonReporter::writePrettyJson(std::ostream& output) const
    {
        output << "{\n";
        output << "  \"generated\": \"" << formatIsoTimestamp(Utils::now()) << "\",\n";

        // Summary block
        output << "  \"summary\": " << summaryToJson(m_report) << ",\n";

        // Optional processed file
        output << "  \"processedFile\": ";
        if (m_report.processedFile().has_value())
            output << "\"" << escapeJsonString(*m_report.processedFile()) << "\"";
        else
            output << "null";
        output << ",\n";

        // Anomalies
        output << "  \"anomalyCount\": " << m_anomalies.size() << ",\n";
        output << "  \"anomalies\": [\n";
        for (std::size_t i = 0; i < m_anomalies.size(); ++i)
        {
            output << "    " << anomalyToJson(m_anomalies[i]);
            output << (i + 1 < m_anomalies.size() ? "," : "") << "\n";
        }
        output << "  ]\n";
        output << "}\n";
    }

    JsonReporter& getJsonReporter()
    {
        static JsonReporter instance(JsonReporter::PrettyPrint::COMPACT);
        return instance;
    }

} // namespace Report
} // namespace LogTool
