#pragma once

#include <vector>
#include <unordered_map>
#include <deque>
#include <mutex>
#include <string>
#include "core/LogEntry.hpp"
#include "utils/TimeUtils.hpp"

namespace LogTool
{
    namespace Analysis
    {
        /**
         * PatternAnalyzer
         *
         * Responsibilities:
         *  - Detect repeating error sequences and failure chains
         *  - Identify common event patterns across sources/levels
         *  - Track event order and transitions (A→B→C patterns)
         *  - Find unusual or never-before-seen message patterns
         *
         * Design notes:
         *  - Uses n-gram style analysis for message sequences
         *  - Maintains sliding window of recent events for pattern detection
         *  - Thread-safe for concurrent log processing
         *  - Efficient hash-based pattern storage
         */
        class PatternAnalyzer
        {
        public:
            struct Pattern
            {
                std::string signature;        // Hashed pattern identifier
                std::size_t frequency = 0;    // How often this pattern occurs
                std::vector<core::LogEntry> examples;  // Sample instances
                Utils::TimePoint firstSeen;
                Utils::TimePoint lastSeen;
            };

            struct PatternStats
            {
                std::size_t totalPatterns = 0;
                std::size_t repeatingPatterns = 0;
                std::size_t errorChains = 0;
                std::unordered_map<std::string, std::size_t> topPatterns;
                std::vector<Pattern> suspiciousPatterns;  // Low frequency, high severity
            };

            /// Default: 10-event sliding window for sequence analysis
            PatternAnalyzer();

            // Non-copyable/moveable due to internal analysis state
            PatternAnalyzer(const PatternAnalyzer&) = delete;
            PatternAnalyzer& operator=(const PatternAnalyzer&) = delete;
            PatternAnalyzer(PatternAnalyzer&&) = delete;
            PatternAnalyzer& operator=(PatternAnalyzer&&) = delete;

            /**
             * Add LogEntry to pattern analysis stream.
             * Updates sequence tracking and pattern frequency counters.
             * Thread-safe.
             */
            void addEntry(const core::LogEntry& entry);

            /**
             * Get comprehensive pattern analysis statistics.
             * Thread-safe read access.
             */
            PatternStats getStats() const;

            /**
             * Detect suspicious patterns:
             *  - Repeating error sequences
             *  - Never-before-seen high-severity messages
             *  - Unusual event transitions
             */
            std::vector<std::string> detectAnomalies() const;

            /**
             * Reset all pattern tracking (start fresh analysis).
             */
            void reset();

            // Configuration
            std::size_t sequenceWindowSize() const noexcept { return m_sequenceWindowSize; }
            void setSequenceWindowSize(std::size_t size) noexcept;

            std::size_t maxPatternExamples() const noexcept { return m_maxPatternExamples; }
            void setMaxPatternExamples(std::size_t count) noexcept;

            Utils::seconds patternTimeout() const noexcept { return m_patternTimeout; }
            void setPatternTimeout(Utils::seconds timeout) noexcept;

        private:
            /// Compact event signature for pattern matching (source+level+first_words)
            struct EventSignature
            {
                std::string source;
                core::LogLevel level;  // Use core::LogLevel (correct namespace)
                std::string messagePrefix;  // First 3 words of message

                bool operator==(const EventSignature& other) const;
                struct Hash;
            };

            /// Sequence of N consecutive events (n-gram)
            using EventSequence = std::vector<EventSignature>;

            /// Extract signature from LogEntry (hashable identifier)
            EventSignature createSignature(const core::LogEntry& entry) const;

            /// Create unique identifier for event sequence
            std::string sequenceToSignature(const EventSequence& sequence) const;

            /// Update pattern frequency and examples under lock
            void updatePatternUnlocked(const EventSequence& sequence, 
                                     const core::LogEntry& latestEntry);

            /// Check if sequence represents an error chain
            bool isErrorChain(const EventSequence& sequence) const;
            bool isErrorChainFromSignature(const std::string& sig) const;

            /// Check if pattern is high severity
            bool isHighSeverityPattern(const std::string& sig) const;

        private:
            mutable std::mutex m_mutex;

            // Recent events for sequence analysis (sliding window)
            std::deque<core::LogEntry> m_recentEvents;

            // Pattern frequency tracking
            std::unordered_map<std::string, Pattern> m_patterns;
            std::unordered_map<std::string, std::size_t> m_sequenceCounts;

            // Configuration parameters
            std::size_t m_sequenceWindowSize = 10;        // Analyze 10-event sequences
            std::size_t m_maxPatternExamples = 3;         // Store 3 examples per pattern
            Utils::seconds m_patternTimeout = std::chrono::minutes(30);  // Expire old patterns
        };

    } // namespace Analysis
} // namespace LogTool
