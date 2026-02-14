#pragma once

#include <iostream>
#include <memory>
#include <vector>
#include "core/Report.hpp"
#include "core/Anomaly.hpp"
#include "utils/TimeUtils.hpp"
#include "utils/Logger.hpp"

namespace LogTool
{
    namespace Report
    {
        /**
         * ConsoleReporter
         *
         * Responsibilities:
         *  - Generate rich, human-readable console reports
         *  - Color-coded severity indicators (if terminal supports)
         *  - Formatted tables for statistics and top-N lists
         *  - Real-time streaming capability for live analysis
         *
         * Design notes:
         *  - Standalone reporter (doesn't depend on ReportGenerator)
         *  - Supports both Windows and Unix terminals
         *  - Configurable verbosity and color schemes
         *  - RAII-managed terminal state
         */
        class ConsoleReporter
        {
        public:
            enum class Verbosity
            {
                QUIET,    // Errors only
                NORMAL,   // Summary + critical anomalies
                VERBOSE,  // All anomalies + detailed stats
                DEBUG     // Full analysis breakdown
            };

            /// Default: normal verbosity, auto-detect colors
            ConsoleReporter(Verbosity verbosity = Verbosity::NORMAL);

            // Copyable and lightweight
            ConsoleReporter(const ConsoleReporter&) = default;
            ConsoleReporter& operator=(const ConsoleReporter&) = default;

            /**
             * Generate complete console report from analysis data.
             */
            void generateReport(const core::Report& report);

            /**
             * Stream single anomaly to console (real-time reporting).
             */
            void reportAnomaly(const core::Anomaly& anomaly);

            /**
             * Print summary statistics only.
             */
            void printSummary(const core::Report& report);

            /**
             * Print top-N sources/messages table.
             */
            void printTopSources(const std::vector<std::pair<std::string, std::size_t>>& sources,
                               std::size_t limit = 10);

            /**
             * Flush output and restore terminal state.
             */
            void flush();

            // Configuration
            void setVerbosity(Verbosity level) noexcept;
            void setEnableColors(bool enable) noexcept;
            void setMaxAnomalies(std::size_t count) noexcept;

        private:
            /// Severity-to-color mapping (ANSI/VT100 sequences)
            static const char* getSeverityColor(double severity);
            static void printSeverityBar(std::ostream& os, double severity, int width = 20);

            /// Table formatting helpers
            void printTableHeader(std::ostream& os, const std::vector<std::string>& headers);
            void printTableRow(std::ostream& os, const std::vector<std::string>& cells);
            void printTableSeparator(std::ostream& os, int columns);

            /// Format anomaly details with proper indentation
            void formatAnomalyDetails(std::ostream& os, const core::Anomaly& anomaly) const;

            /// Terminal control sequences
            void enableColors() noexcept;
            void disableColors() noexcept;
            void resetTerminal() noexcept;

        private:
            Verbosity m_verbosity;
            bool m_colorsEnabled;
            std::size_t m_maxAnomalies;
            std::ostream* m_output;
        };

        /**
         * Global console reporter singleton (thread-safe).
         * Usage: ConsoleReporter::get().reportAnomaly(anomaly);
         */
        ConsoleReporter& getConsoleReporter();

    } // namespace Report
} // namespace LogTool
