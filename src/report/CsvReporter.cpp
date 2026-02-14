#include "report/CsvReporter.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "utils/Logger.hpp"
#include "utils/StringUtils.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
namespace Report
{
    CsvReporter::CsvReporter(ExportMode mode)
        : m_exportMode(mode),
          m_maxAnomalies(1000),
          m_minSeverity(0.0),
          m_includeTimestamps(true)
    {
        Utils::getLogger().debug(
            "CsvReporter initialized (mode: " + std::to_string(static_cast<int>(mode)) + ")");
    }

    void CsvReporter::generateReport(const core::Report& report)
    {
        m_report = report;

        // Filter anomalies into our local view (stable + deterministic)
        m_anomalies = report.anomalies();

        // Normalize the enum severity to 0..1 scale using a common 0..4 range.
        const int maxSev = 4;
        m_anomalies.erase(
            std::remove_if(m_anomalies.begin(), m_anomalies.end(), [&](const core::Anomaly& a) {
                const int sev = static_cast<int>(a.severity());
                const double sevNorm = (maxSev <= 0)
                                          ? 0.0
                                          : std::clamp(static_cast<double>(sev) / maxSev, 0.0, 1.0);
                return sevNorm + 1e-12 < m_minSeverity;
            }),
            m_anomalies.end());

        std::sort(m_anomalies.begin(), m_anomalies.end(), [](const core::Anomaly& a, const core::Anomaly& b) {
            if (a.severity() != b.severity())
                return static_cast<int>(a.severity()) > static_cast<int>(b.severity());
            if (a.score() != b.score())
                return a.score() > b.score();
            return a.windowEnd() > b.windowEnd();
        });

        if (m_maxAnomalies > 0 && m_anomalies.size() > m_maxAnomalies)
            m_anomalies.resize(m_maxAnomalies);

        Utils::getLogger().debug(
            "CSV report prepared: " + std::to_string(m_anomalies.size()) + " anomalies");
    }

    void CsvReporter::writeCsv(std::ostream& output, bool includeHeader) const
    {
        // This reporter focuses on a spreadsheet-friendly anomaly table.
        // Summary tables can be expanded later if needed.
        if (m_exportMode == ExportMode::SUMMARY_TABLES)
        {
            if (includeHeader)
                writeCsvRow(output, {"Metric", "Value"});
            writeCsvRow(output, {"Analysis Start", Utils::toIso8601(m_report.analysisStart())});
            writeCsvRow(output, {"Analysis End", Utils::toIso8601(m_report.analysisEnd())});
            writeCsvRow(output, {"Total Events", std::to_string(m_report.totalEntries())});
            writeCsvRow(output, {"Total Errors", std::to_string(m_report.totalErrorEvents())});
            writeCsvRow(output, {"Total Warnings", std::to_string(m_report.totalWarningEvents())});
            writeCsvRow(output, {"Anomalies", std::to_string(m_anomalies.size())});
            return;
        }

        if (includeHeader)
        {
            // Keep headers consistent with ReportGenerator::renderCsv
            if (m_includeTimestamps)
                writeCsvRow(output, {"WindowStart", "WindowEnd", "Type", "Severity", "Score", "Source", "Description"});
            else
                writeCsvRow(output, {"Type", "Severity", "Score", "Source", "Description"});
        }

        for (const auto& a : getExportAnomalies())
        {
            const std::string src = a.source().value_or("");

            std::vector<std::string> row;
            if (m_includeTimestamps)
            {
                row.push_back(Utils::toIso8601(a.windowStart()));
                row.push_back(Utils::toIso8601(a.windowEnd()));
            }
            row.push_back(std::to_string(static_cast<int>(a.type())));
            row.push_back(std::to_string(static_cast<int>(a.severity())));
            {
                std::ostringstream s;
                s << std::fixed << std::setprecision(6) << a.score();
                row.push_back(s.str());
            }
            row.push_back(src);
            row.push_back(a.description());

            writeCsvRow(output, row);
        }
    }

    std::string CsvReporter::getCsvString(bool includeHeader) const
    {
        std::ostringstream oss;
        writeCsv(oss, includeHeader);
        return oss.str();
    }

    std::string CsvReporter::anomaliesToCsv(bool includeHeader) const
    {
        // Same as writeCsv for current implementation
        std::ostringstream oss;
        const auto prevMode = m_exportMode;
        (void)prevMode;
        writeCsv(oss, includeHeader);
        return oss.str();
    }

    std::string CsvReporter::summaryToCsv(bool includeHeader) const
    {
        std::ostringstream oss;
        // Temporarily render summary regardless of export mode
        if (includeHeader)
            writeCsvRow(oss, {"Metric", "Value"});
        writeCsvRow(oss, {"Analysis Start", Utils::toIso8601(m_report.analysisStart())});
        writeCsvRow(oss, {"Analysis End", Utils::toIso8601(m_report.analysisEnd())});
        writeCsvRow(oss, {"Total Events", std::to_string(m_report.totalEntries())});
        writeCsvRow(oss, {"Total Errors", std::to_string(m_report.totalErrorEvents())});
        writeCsvRow(oss, {"Total Warnings", std::to_string(m_report.totalWarningEvents())});
        writeCsvRow(oss, {"Anomalies", std::to_string(m_anomalies.size())});
        return oss.str();
    }

    void CsvReporter::setExportMode(ExportMode mode) noexcept
    {
        m_exportMode = mode;
    }

    void CsvReporter::setMaxAnomalies(std::size_t count) noexcept
    {
        m_maxAnomalies = count;
    }

    void CsvReporter::setMinSeverity(double threshold) noexcept
    {
        m_minSeverity = std::clamp(threshold, 0.0, 1.0);
    }

    void CsvReporter::setIncludeTimestamps(bool include) noexcept
    {
        m_includeTimestamps = include;
    }

    // ---- RFC 4180 helpers ----

    std::string CsvReporter::escapeCsvField(const std::string& field)
    {
        if (field.find_first_of(",\"\r\n") == std::string::npos)
            return field;

        std::string result;
        result.reserve(field.size() + 2);
        result.push_back('"');
        for (char c : field)
        {
            if (c == '"')
                result += "\"\"";
            else
                result.push_back(c);
        }
        result.push_back('"');
        return result;
    }

    void CsvReporter::writeCsvRow(std::ostream& os, const std::vector<std::string>& fields)
    {
        for (std::size_t i = 0; i < fields.size(); ++i)
        {
            if (i) os << ",";
            os << escapeCsvField(fields[i]);
        }
        os << "\r\n";
    }

    std::vector<std::string> CsvReporter::getAnomalyHeaders()
    {
        return {"WindowStart", "WindowEnd", "Type", "Severity", "Score", "Source", "Description"};
    }

    std::vector<std::string> CsvReporter::getSummaryHeaders()
    {
        return {"Metric", "Value"};
    }

    std::vector<core::Anomaly> CsvReporter::getExportAnomalies() const
    {
        return m_anomalies;
    }

    CsvReporter& getCsvReporter()
    {
        static CsvReporter instance(CsvReporter::ExportMode::ANOMALIES_ONLY);
        return instance;
    }

} // namespace Report
} // namespace LogTool
