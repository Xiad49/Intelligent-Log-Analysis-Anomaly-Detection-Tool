#pragma once

#include <ostream>
#include <memory>
#include <vector>
#include <string>
#include "core/Report.hpp"
#include "core/Anomaly.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
    namespace Report
    {
        /**
         * JsonReporter
         *
         * Responsibilities:
         *  - Generate structured JSON output for machine consumption
         *  - Support dashboard integration (Grafana, Kibana, etc.)
         *  - Proper JSON escaping and formatting
         *  - Configurable detail levels and filtering
         *
         * Design notes:
         *  - Header-only JSON generation (no external dependencies)
         *  - Proper escaping for all fields
         *  - Nested structures for analysis results
         *  - Compact and pretty-print modes
         *  - RFC 8259 compliant JSON
         */
        class JsonReporter
        {
        public:
            enum class PrettyPrint
            {
                COMPACT,  // Single line, minimal whitespace
                PRETTY    // Indented, human-readable JSON
            };

            /// Default: compact output
            JsonReporter(PrettyPrint pretty = PrettyPrint::COMPACT);

            // Lightweight and copyable
            JsonReporter(const JsonReporter&) = default;
            JsonReporter& operator=(const JsonReporter&) = default;

            /**
             * Generate complete JSON report from analysis data.
             */
            void generateReport(const core::Report& report);

            /**
             * Write JSON to output stream.
             */
            void writeJson(std::ostream& output) const;

            /**
             * Get JSON as string.
             */
            std::string getJsonString() const;

            /**
             * Stream single anomaly as JSON object.
             */
            std::string anomalyToJson(const core::Anomaly& anomaly) const;

            /**
             * Stream summary statistics as JSON.
             */
            std::string summaryToJson(const core::Report& stats) const;

            // Configuration
            void setPrettyPrint(PrettyPrint mode) noexcept;
            void setMaxAnomalies(std::size_t count) noexcept;
            void setIncludeSamples(bool include) noexcept;
            void setFilterSeverity(double minSeverity) noexcept;

        private:
            /// JSON escaping for strings (RFC 8259)
            static std::string escapeJsonString(const std::string& str);

            /// Compact and pretty JSON writers
            void writeCompactJson(std::ostream& output) const;
            void writePrettyJson(std::ostream& output) const;

            /// Format timestamp as ISO8601
            static std::string formatIsoTimestamp(Utils::TimePoint tp);

            /// Minimal hex helper for JSON \u00XX escaping (no dependency on Utils::toHex)
            static std::string toHex(unsigned int value, std::size_t width);

        private:
            core::Report m_report;
            std::vector<core::Anomaly> m_anomalies; // filtered/sorted view
            PrettyPrint m_prettyPrint;
            std::size_t m_maxAnomalies;
            bool m_includeSamples;
            double m_minSeverity;
        };

        /**
         * Global JSON reporter (thread-safe singleton).
         * Usage: JsonReporter::get().generateReport(report);
         */
        JsonReporter& getJsonReporter();

    } // namespace Report
} // namespace LogTool
