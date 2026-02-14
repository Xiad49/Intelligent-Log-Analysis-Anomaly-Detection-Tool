#include "report/ConsoleReporter.hpp"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
  #include <io.h>      // _isatty, _fileno
#else
  #include <unistd.h>  // isatty, fileno
#endif

namespace LogTool
{
namespace Report
{
    namespace
    {
        // Small, portable isatty wrapper.
        bool stdoutIsTty() noexcept
        {
        #if defined(_WIN32)
            return _isatty(_fileno(stdout)) != 0;
        #else
            return ::isatty(::fileno(stdout)) != 0;
        #endif
        }

        // Convert core::Anomaly::Severity (enum) to a 0..1-ish value for bars/colors.
        // We don't know the exact enum range here, so we clamp against a reasonable max.
        double severityToNormalized(const core::Anomaly& a) noexcept
        {
            const int s = static_cast<int>(a.severity());
            const int maxS = 4; // common: 0..4 (Low..Critical)
            if (s <= 0) return 0.0;
            if (s >= maxS) return 1.0;
            return static_cast<double>(s) / static_cast<double>(maxS);
        }

        std::vector<std::pair<std::string, std::size_t>>
        computeTopSources(const core::Report& report)
        {
            std::vector<std::pair<std::string, std::size_t>> top;
            top.reserve(report.sourceStatistics().size());

            for (const auto& [src, st] : report.sourceStatistics())
                top.emplace_back(src, static_cast<std::size_t>(st.totalEvents));

            std::sort(top.begin(), top.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });

            return top;
        }

        std::string severityLabel(const core::Anomaly& a)
        {
            // We only know it is an enum; keep it simple and stable.
            return std::to_string(static_cast<int>(a.severity()));
        }

        std::string typeLabel(const core::Anomaly& a)
        {
            return std::to_string(static_cast<int>(a.type()));
        }
    } // namespace

    ConsoleReporter::ConsoleReporter(Verbosity verbosity)
        : m_verbosity(verbosity),
          m_colorsEnabled(true),
          m_maxAnomalies(25),
          m_output(&std::cout)
    {
        // Auto-detect terminal color support.
        // NOTE: Windows 10+ terminals usually support ANSI, but _isatty is still a good baseline.
        m_colorsEnabled = stdoutIsTty();
    }

    void ConsoleReporter::generateReport(const core::Report& report)
    {
        const auto& anomalies = report.anomalies();
        if (m_verbosity == Verbosity::QUIET && anomalies.empty())
            return;

        *m_output << "\n=== LOG ANALYSIS REPORT ===\n";
        *m_output << "Generated:      " << Utils::formatTimestamp(Utils::now()) << "\n";
        *m_output << "Analysis Start: " << Utils::formatTimestamp(report.analysisStart()) << "\n";
        *m_output << "Analysis End:   " << Utils::formatTimestamp(report.analysisEnd()) << "\n";
        *m_output << "Total Events:   " << report.totalEntries() << "\n";
        *m_output << "Total Errors:   " << report.totalErrorEvents() << "\n";
        *m_output << "Total Warnings: " << report.totalWarningEvents() << "\n";
        *m_output << "Anomalies:      " << anomalies.size() << "\n";
        if (report.processedFile().has_value())
            *m_output << "File:           " << *report.processedFile() << "\n";
        *m_output << "\n";

        // Top sources
        {
            const auto top = computeTopSources(report);
            if (!top.empty() && m_verbosity >= Verbosity::NORMAL)
            {
                *m_output << "Top Sources (Top 10)\n";
                printTopSources(top, 10);
                *m_output << "\n";
            }
        }

        // Anomalies
        if (anomalies.empty())
        {
            *m_output << "No anomalies detected.\n";
            flush();
            return;
        }

        std::size_t limit = anomalies.size();
        if (m_maxAnomalies > 0)
            limit = std::min<std::size_t>(limit, m_maxAnomalies);

        *m_output << "Anomalies (showing " << limit << " of " << anomalies.size() << ")\n";
        *m_output << std::string(70, '-') << "\n";

        for (std::size_t i = 0; i < limit; ++i)
        {
            formatAnomalyDetails(*m_output, anomalies[i]);
            *m_output << "\n";
        }

        if (limit < anomalies.size())
            *m_output << "... and " << (anomalies.size() - limit) << " more\n";

        *m_output << "=== END REPORT ===\n\n";
        flush();
    }

    void ConsoleReporter::reportAnomaly(const core::Anomaly& anomaly)
    {
        if (m_verbosity == Verbosity::QUIET)
            return;

        formatAnomalyDetails(*m_output, anomaly);
        *m_output << "\n";
        flush();
    }

    void ConsoleReporter::printSummary(const core::Report& report)
    {
        *m_output << "SUMMARY: "
                  << report.totalEntries() << " events, "
                  << report.anomalies().size() << " anomalies\n";
        flush();
    }

    void ConsoleReporter::printTopSources(
        const std::vector<std::pair<std::string, std::size_t>>& sources,
        std::size_t limit)
    {
        std::vector<std::pair<std::string, std::size_t>> top = sources;
        if (limit > 0 && top.size() > limit)
            top.resize(limit);

        const int colSource = 32;
        const int colCount  = 12;

        *m_output << std::left << std::setw(colSource) << "Source"
                  << std::right << std::setw(colCount) << "Count"
                  << "\n";
        *m_output << std::string(colSource + colCount, '-') << "\n";

        for (const auto& [src, count] : top)
        {
            *m_output << std::left << std::setw(colSource) << src
                      << std::right << std::setw(colCount) << count
                      << "\n";
        }
    }

    void ConsoleReporter::flush()
    {
        m_output->flush();
    }

    void ConsoleReporter::setVerbosity(Verbosity level) noexcept
    {
        m_verbosity = level;
    }

    void ConsoleReporter::setEnableColors(bool enable) noexcept
    {
        m_colorsEnabled = enable;
    }

    void ConsoleReporter::setMaxAnomalies(std::size_t count) noexcept
    {
        m_maxAnomalies = count;
    }

    // ---- Private helpers ----

    const char* ConsoleReporter::getSeverityColor(double severityNorm)
    {
        // ANSI escape codes. Caller decides whether to use them.
        if (severityNorm >= 0.75) return "\033[91m"; // bright red
        if (severityNorm >= 0.50) return "\033[93m"; // yellow
        if (severityNorm >= 0.25) return "\033[33m"; // dark yellow
        return "\033[97m"; // white
    }

    void ConsoleReporter::printSeverityBar(std::ostream& os, double severityNorm, int width)
    {
        if (width <= 0)
            return;

        const int full  = std::clamp(static_cast<int>(severityNorm * width + 0.5), 0, width);
        const int empty = width - full;

        // Draw only; color is handled by the caller.
        os << std::string(full, '=') << std::string(empty, '.');
    }

    void ConsoleReporter::printTableHeader(std::ostream& os, const std::vector<std::string>& headers)
    {
        // Kept for compatibility; current implementation uses simple text.
        for (std::size_t i = 0; i < headers.size(); ++i)
        {
            if (i) os << " | ";
            os << headers[i];
        }
        os << "\n";
    }

    void ConsoleReporter::printTableRow(std::ostream& os, const std::vector<std::string>& cells)
    {
        for (std::size_t i = 0; i < cells.size(); ++i)
        {
            if (i) os << " | ";
            os << cells[i];
        }
        os << "\n";
    }

    void ConsoleReporter::printTableSeparator(std::ostream& os, int columns)
    {
        if (columns <= 0) columns = 1;
        os << std::string(static_cast<std::size_t>(columns) * 10, '-') << "\n";
    }

    void ConsoleReporter::formatAnomalyDetails(std::ostream& os, const core::Anomaly& anomaly) const
    {
        const double sevNorm = severityToNormalized(anomaly);

        const bool useColor = m_colorsEnabled;
        const char* color = useColor ? getSeverityColor(sevNorm) : "";
        const char* reset = useColor ? "\033[0m" : "";

        // Header line
        os << "[sev=" << severityLabel(anomaly) << "] ";
        if (m_verbosity >= Verbosity::VERBOSE)
        {
            os << "[type=" << typeLabel(anomaly) << "] ";
            os << "[score=" << std::fixed << std::setprecision(4) << anomaly.score() << "] ";
        }

        const std::string src = anomaly.source().value_or("(unknown)");
        os << src << " ";
        os << Utils::formatTimestamp(anomaly.windowEnd(), "%H:%M:%S");
        os << "\n";

        // Severity bar
        os << "  ";
        if (useColor) os << color;
        printSeverityBar(os, sevNorm, 20);
        if (useColor) os << reset;
        os << "\n";

        // Description
        os << "  ";
        if (useColor) os << color;
        os << anomaly.description();
        if (useColor) os << reset;
        os << "\n";

        if (m_verbosity >= Verbosity::VERBOSE)
        {
            os << "  Window: "
               << Utils::formatTimestamp(anomaly.windowStart())
               << " -> "
               << Utils::formatTimestamp(anomaly.windowEnd())
               << "\n";
        }
    }

    void ConsoleReporter::enableColors() noexcept
    {
        m_colorsEnabled = true;
    }

    void ConsoleReporter::disableColors() noexcept
    {
        m_colorsEnabled = false;
    }

    void ConsoleReporter::resetTerminal() noexcept
    {
        // If colors are enabled, emit reset.
        if (m_colorsEnabled && m_output)
            (*m_output) << "\033[0m";
    }

    ConsoleReporter& getConsoleReporter()
    {
        static ConsoleReporter instance(ConsoleReporter::Verbosity::NORMAL);
        return instance;
    }

} // namespace Report
} // namespace LogTool
