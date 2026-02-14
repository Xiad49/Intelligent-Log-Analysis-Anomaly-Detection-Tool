#pragma once

#include <ostream>
#include <vector>
#include <memory>
#include "core/Report.hpp"
#include "core/Anomaly.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
    namespace Report
    {
        /**
         * CsvReporter
         *
         * Responsibilities:
         *  - Generate RFC 4180-compliant CSV for Excel/LibreOffice
         *  - Proper quoting and escaping of complex fields
         *  - Multiple export modes (anomalies, summary, full dataset)
         *  - Spreadsheet-optimized column ordering
         *
         * Design notes:
         *  - Header-only CSV generation (no external dependencies)
         *  - RFC 4180 compliant quoting/escaping
         *  - Configurable column selection and filtering
         *  - Optimized for bulk data export
         */
        class CsvReporter
        {
        public:
            enum class ExportMode
            {
                ANOMALIES_ONLY,    // Just anomalies table
                SUMMARY_TABLES,    // Summary stats + top-N tables
                FULL_REPORT,       // Complete analysis with all tables
                RAW_EVENTS         // Original log events (if available)
            };

            /// Default: anomalies only
            CsvReporter(ExportMode mode = ExportMode::ANOMALIES_ONLY);

            // Lightweight and copyable
            CsvReporter(const CsvReporter&) = default;
            CsvReporter& operator=(const CsvReporter&) = default;

            /**
             * Generate CSV data from analysis report.
             */
            void generateReport(const core::Report& report);

            /**
             * Write CSV to output stream with header row.
             */
            void writeCsv(std::ostream& output, bool includeHeader = true) const;

            /**
             * Get complete CSV as string.
             */
            std::string getCsvString(bool includeHeader = true) const;

            /**
             * Export only anomalies as CSV.
             */
            std::string anomaliesToCsv(bool includeHeader = true) const;

            /**
             * Export summary statistics as CSV table.
             */
            std::string summaryToCsv(bool includeHeader = true) const;

            // Configuration
            void setExportMode(ExportMode mode) noexcept;
            void setMaxAnomalies(std::size_t count) noexcept;
            void setMinSeverity(double threshold) noexcept;
            void setIncludeTimestamps(bool include) noexcept;

        private:
            /// RFC 4180 CSV escaping (handles quotes, commas, newlines)
            static std::string escapeCsvField(const std::string& field);

            /// Write CSV row (vector of fields)
            static void writeCsvRow(std::ostream& os, const std::vector<std::string>& fields);

            /// Generate standard anomaly CSV headers
            static std::vector<std::string> getAnomalyHeaders();

            /// Generate summary statistics headers
            static std::vector<std::string> getSummaryHeaders();

            /// Filter and sort anomalies for export
            std::vector<core::Anomaly> getExportAnomalies() const;

        private:
            core::Report m_report;
            std::vector<core::Anomaly> m_anomalies; // filtered/sorted view
            ExportMode m_exportMode;
            std::size_t m_maxAnomalies;
            double m_minSeverity;
            bool m_includeTimestamps;
        };

        /**
         * Global CSV reporter singleton for easy access.
         * Usage: CsvReporter::get().generateReport(report);
         */
        CsvReporter& getCsvReporter();

    } // namespace Report
} // namespace LogTool
