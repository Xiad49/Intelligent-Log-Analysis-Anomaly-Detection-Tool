#pragma once

#include <string>
#include <vector>
#include <memory>
#include <ostream>
#include <mutex>
#include "core/Report.hpp"
#include "core/Anomaly.hpp"
#include "analysis/FrequencyAnalyzer.hpp"
#include "analysis/TimeWindowAnalyzer.hpp"
#include "analysis/PatternAnalyzer.hpp"
#include "anomaly/RuleBasedDetector.hpp"
#include "anomaly/StatisticalDetector.hpp"
#include "anomaly/SpikeDetector.hpp"

namespace LogTool
{
    namespace Report
    {
        /**
         * ReportGenerator
         *
         * Responsibilities:
         *  - Aggregate results from all analysis modules
         *  - Generate human-readable and machine-readable reports
         *  - Support multiple output formats (console, JSON, CSV)
         *  - Rank anomalies by severity and provide summary statistics
         *
         * Design notes:
         *  - RAII-managed report state
         *  - Strategy pattern for different output formats
         *  - Thread-safe aggregation from concurrent analysis modules
         *  - Configurable report depth and detail levels
         */
        class ReportGenerator
        {
        public:
            enum class OutputFormat
            {
                CONSOLE,  // Human-readable colored console output
                JSON,     // Structured JSON for dashboards
                CSV,      // Spreadsheet-friendly CSV
                SUMMARY   // Executive summary only
            };

            /// Default: console output, full detail
            ReportGenerator(OutputFormat format = OutputFormat::CONSOLE);

            // Non-copyable due to owned reporters
            ReportGenerator(const ReportGenerator&) = delete;
            ReportGenerator& operator=(const ReportGenerator&) = delete;

            ReportGenerator(ReportGenerator&&) = default;
            ReportGenerator& operator=(ReportGenerator&&) = default;

            /**
             * Aggregate analysis results into comprehensive report.
             * Automatically ranks anomalies by severity.
             */
            void generateReport(const core::Report& reportData);

            /**
             * Write report to specified output stream.
             * Returns true on success.
             */
            bool writeReport(std::ostream& output) const;

            /**
             * Write report to file.
             */
            bool writeReportToFile(const std::string& filePath);

            /**
             * Get report as string (for logging or return values).
             */
            std::string getReportString() const;

            /**
             * Add custom analysis module results.
             */
            template<typename AnalyzerType>
            void addAnalyzerResults(const AnalyzerType& analyzer);

            // Configuration
            void setFormat(OutputFormat format) noexcept;
            void setMaxAnomalies(std::size_t count) noexcept;
            void setIncludeSamples(bool include) noexcept;

        private:
            /// Rank anomalies by severity, recency, and impact
            static bool anomalySeverityComparator(const core::Anomaly& a, 
                                                const core::Anomaly& b);
            
            std::vector<core::Anomaly> m_sortedAnomalies;
            /// Generate section headers and statistics
            void generateSummarySection(std::ostream& output) const;
            void generateAnomalySection(std::ostream& output) const;
            void generateAnalysisSection(std::ostream& output) const;

            /// Format-specific rendering
            void renderConsole(std::ostream& output) const;
            void renderJson(std::ostream& output) const;
            void renderCsv(std::ostream& output) const;

        private:
            mutable std::mutex m_mutex;
            core::Report m_reportData;
            OutputFormat m_format;
            std::size_t m_maxAnomalies = 50;
            bool m_includeSamples = true;
        };

        /**
         * Convenience factory functions for common report types
         */
        namespace Factory
        {
            std::unique_ptr<ReportGenerator> createConsoleReport();
            std::unique_ptr<ReportGenerator> createJsonReport();
            std::unique_ptr<ReportGenerator> createCsvReport();
        }

    } // namespace Report
} // namespace LogTool
