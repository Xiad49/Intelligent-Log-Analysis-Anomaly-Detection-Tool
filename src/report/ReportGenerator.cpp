#include "report/ReportGenerator.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

#include "utils/Logger.hpp"
#include "utils/StringUtils.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
namespace Report
{
    // ---- Helpers (local to this translation unit) ----

    static std::vector<std::pair<std::string, std::uint64_t>>
    computeTopSources(const core::Report& report)
    {
        std::vector<std::pair<std::string, std::uint64_t>> top;
        top.reserve(report.sourceStatistics().size());

        for (const auto& [src, st] : report.sourceStatistics())
            top.emplace_back(src, st.totalEvents);

        std::sort(top.begin(), top.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });

        return top;
    }

    // ---- ReportGenerator ----

    ReportGenerator::ReportGenerator(OutputFormat format)
        : m_format(format)
    {
        Utils::getLogger().debug(
            "ReportGenerator created (" + std::to_string(static_cast<int>(format)) + ")");
    }

    void ReportGenerator::generateReport(const core::Report& reportData)
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        m_reportData = reportData;

        // Copy anomalies so we can sort/truncate without mutating core::Report
        m_sortedAnomalies = m_reportData.anomalies();

        std::sort(m_sortedAnomalies.begin(), m_sortedAnomalies.end(),
                  &ReportGenerator::anomalySeverityComparator);

        if (m_maxAnomalies > 0 && m_sortedAnomalies.size() > m_maxAnomalies)
            m_sortedAnomalies.resize(m_maxAnomalies);

        Utils::getLogger().info(
            "Report generated: " + std::to_string(m_sortedAnomalies.size()) +
            " anomalies, " + std::to_string(m_reportData.totalEntries()) + " events");
    }

    bool ReportGenerator::writeReport(std::ostream& output) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        switch (m_format)
        {
            case OutputFormat::CONSOLE:
                renderConsole(output);
                break;
            case OutputFormat::JSON:
                renderJson(output);
                break;
            case OutputFormat::CSV:
                renderCsv(output);
                break;
            case OutputFormat::SUMMARY:
                generateSummarySection(output);
                break;
        }

        return output.good();
    }

    bool ReportGenerator::writeReportToFile(const std::string& filePath)
    {
        std::ofstream file(filePath);
        if (!file.is_open())
        {
            Utils::getLogger().error("Failed to open report file: " + filePath);
            return false;
        }

        return writeReport(file);
    }

    std::string ReportGenerator::getReportString() const
    {
        std::ostringstream oss;
        writeReport(oss);
        return oss.str();
    }

    void ReportGenerator::setFormat(OutputFormat format) noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_format = format;
    }

    void ReportGenerator::setMaxAnomalies(std::size_t count) noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_maxAnomalies = count;
    }

    void ReportGenerator::setIncludeSamples(bool include) noexcept
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_includeSamples = include;
    }

    // ---- Comparator ----
    bool ReportGenerator::anomalySeverityComparator(const core::Anomaly& a, const core::Anomaly& b)
    {
        // Primary: severity (higher first). Assumes severity is an enum (Low..Critical)
        if (a.severity() != b.severity())
            return static_cast<int>(a.severity()) > static_cast<int>(b.severity());

        // Secondary: score (higher first), if available
        if (a.score() != b.score())
            return a.score() > b.score();

        // Tertiary: recency (newer windowEnd first)
        if (a.windowEnd() != b.windowEnd())
            return a.windowEnd() > b.windowEnd();

        // Last: description alphabetical
        return a.description() < b.description();
    }

    // ---- Rendering ----

    void ReportGenerator::renderConsole(std::ostream& output) const
    {
        output << "\n=== LOG ANALYSIS REPORT ===\n";
        output << "Generated: " << Utils::formatTimestamp(Utils::now()) << "\n";
        output << "Analysis Start: " << Utils::formatTimestamp(m_reportData.analysisStart()) << "\n";
        output << "Analysis End:   " << Utils::formatTimestamp(m_reportData.analysisEnd()) << "\n";
        output << "Total Events:   " << m_reportData.totalEntries() << "\n";
        output << "Anomalies:      " << m_sortedAnomalies.size() << "\n";

        if (m_reportData.processedFile().has_value())
            output << "File:           " << *m_reportData.processedFile() << "\n";

        output << "\n";

        generateSummarySection(output);
        generateAnomalySection(output);
        generateAnalysisSection(output);

        output << "=== END REPORT ===\n\n";
    }

    void ReportGenerator::renderJson(std::ostream& output) const
    {
        output << "{\n";
        output << "  \"generated\": \"" << Utils::toIso8601(Utils::now()) << "\",\n";
        output << "  \"analysisStart\": \"" << Utils::toIso8601(m_reportData.analysisStart()) << "\",\n";
        output << "  \"analysisEnd\": \"" << Utils::toIso8601(m_reportData.analysisEnd()) << "\",\n";
        output << "  \"totalEvents\": " << m_reportData.totalEntries() << ",\n";
        output << "  \"totalErrors\": " << m_reportData.totalErrorEvents() << ",\n";
        output << "  \"totalWarnings\": " << m_reportData.totalWarningEvents() << ",\n";

        output << "  \"processedFile\": ";
        if (m_reportData.processedFile().has_value())
            output << "\"" << Utils::escapeJson(*m_reportData.processedFile()) << "\"";
        else
            output << "null";
        output << ",\n";

        // Top sources
        const auto top = computeTopSources(m_reportData);
        output << "  \"topSources\": [\n";
        {
            const std::size_t n = std::min<std::size_t>(5, top.size());
            for (std::size_t i = 0; i < n; ++i)
            {
                output << "    {\"source\": \"" << Utils::escapeJson(top[i].first)
                       << "\", \"count\": " << top[i].second << "}";
                output << (i + 1 < n ? "," : "") << "\n";
            }
        }
        output << "  ],\n";

        // Anomalies
        output << "  \"anomalies\": [\n";
        for (std::size_t i = 0; i < m_sortedAnomalies.size(); ++i)
        {
            const auto& a = m_sortedAnomalies[i];
            const std::string src = a.source().value_or("");

            output << "    {\n";
            output << "      \"type\": " << static_cast<int>(a.type()) << ",\n";
            output << "      \"severity\": " << static_cast<int>(a.severity()) << ",\n";
            output << "      \"score\": " << std::fixed << std::setprecision(6) << a.score() << ",\n";
            output << "      \"windowStart\": \"" << Utils::toIso8601(a.windowStart()) << "\",\n";
            output << "      \"windowEnd\": \"" << Utils::toIso8601(a.windowEnd()) << "\",\n";
            output << "      \"source\": \"" << Utils::escapeJson(src) << "\",\n";
            output << "      \"description\": \"" << Utils::escapeJson(a.description()) << "\"\n";
            output << "    }" << (i + 1 < m_sortedAnomalies.size() ? "," : "") << "\n";
        }
        output << "  ]\n";
        output << "}\n";
    }

    void ReportGenerator::renderCsv(std::ostream& output) const
    {
        // CSV Header (only fields that actually exist in core::Anomaly)
        output << "WindowStart,WindowEnd,Type,Severity,Score,Source,Description\n";

        for (const auto& a : m_sortedAnomalies)
        {
            const std::string src = a.source().value_or("");

            output << Utils::formatTimestamp(a.windowStart(), "%Y-%m-%dT%H:%M:%S") << ",";
            output << Utils::formatTimestamp(a.windowEnd(), "%Y-%m-%dT%H:%M:%S") << ",";
            output << static_cast<int>(a.type()) << ",";
            output << static_cast<int>(a.severity()) << ",";
            output << std::fixed << std::setprecision(6) << a.score() << ",";
            output << Utils::escapeCsv(src) << ",";
            output << Utils::escapeCsv(a.description()) << "\n";
        }
    }

    void ReportGenerator::generateSummarySection(std::ostream& output) const
    {
        output << "📊 SUMMARY STATISTICS\n";
        output << "====================\n";
        output << "Total Events:   " << m_reportData.totalEntries() << "\n";
        output << "Total Errors:   " << m_reportData.totalErrorEvents() << "\n";
        output << "Total Warnings: " << m_reportData.totalWarningEvents() << "\n";

        const auto top = computeTopSources(m_reportData);
        if (!top.empty())
        {
            output << "\nTop 5 Sources:\n";
            const std::size_t n = std::min<std::size_t>(5, top.size());
            for (std::size_t i = 0; i < n; ++i)
            {
                output << "  " << std::setw(20) << std::left << top[i].first
                       << top[i].second << " events\n";
            }
        }

        output << "\n";
    }

    void ReportGenerator::generateAnomalySection(std::ostream& output) const
    {
        if (m_sortedAnomalies.empty())
        {
            output << "✅ NO ANOMALIES DETECTED\n\n";
            return;
        }

        output << "🚨 TOP ANOMALIES (" << m_sortedAnomalies.size() << ")\n";
        output << "========================\n\n";

        for (std::size_t i = 0; i < m_sortedAnomalies.size(); ++i)
        {
            const auto& a = m_sortedAnomalies[i];
            const std::string src = a.source().value_or("");

            output << "❌ #" << (i + 1) << " ";

            // Severity indicator based on enum (0..3 => 1..4 stars, clamped to 5)
            const int sevInt = static_cast<int>(a.severity());
            const int stars = std::max(1, std::min(5, sevInt + 1));
            output << std::string(stars, '*') << std::string(5 - stars, '-');

            output << "  score=" << std::fixed << std::setprecision(3) << a.score() << "\n";
            output << "   Window: " << Utils::formatTimestamp(a.windowStart())
                   << " -> " << Utils::formatTimestamp(a.windowEnd()) << "\n";
            output << "   Type:   " << static_cast<int>(a.type()) << "\n";
            output << "   Src:    " << (src.empty() ? "(none)" : src) << "\n";
            output << "   Desc:   " << a.description() << "\n\n";
        }
    }

    void ReportGenerator::generateAnalysisSection(std::ostream& output) const
    {
        output << "📈 ANALYSIS BREAKDOWN\n";
        output << "====================\n";

        // By log level
        if (!m_reportData.levelStatistics().empty())
        {
            output << "\nBy Level:\n";
            for (const auto& [lvl, st] : m_reportData.levelStatistics())
            {
                output << "  Level " << static_cast<int>(lvl) << ": "
                       << st.count << " events, "
                       << st.anomalyCount << " anomalies\n";
            }
        }

        // By source (top 10)
        const auto top = computeTopSources(m_reportData);
        if (!top.empty())
        {
            output << "\nBy Source (Top 10):\n";
            const std::size_t n = std::min<std::size_t>(10, top.size());
            for (std::size_t i = 0; i < n; ++i)
            {
                output << "  " << std::setw(20) << std::left << top[i].first
                       << top[i].second << " events\n";
            }
        }

        output << "\n";
    }

} // namespace Report
} // namespace LogTool
