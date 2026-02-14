#pragma once

#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <functional>
#include <atomic>
#include <chrono>
#include <deque>
#include <optional>
#include "core/LogEntry.hpp"
#include "core/Anomaly.hpp"
#include "utils/ConfigLoader.hpp"

namespace LogTool
{
    namespace Anomaly
    {
        /**
         * RuleBasedDetector (Optimized & Dynamic)
         *
         * Key Optimizations:
         *  - Shared mutex for concurrent read access
         *  - Lock-free atomic operations where possible
         *  - Rule caching and lazy compilation
         *  - Memory pool for frequent allocations
         *  - Time-window optimization with circular buffers
         *  - Plugin-based rule system for dynamic extensibility
         *
         * Dynamic Features:
         *  - Hot-reload rules without restart
         *  - Runtime rule registration via plugins
         *  - Dynamic severity adjustment based on context
         *  - Adaptive threshold tuning
         *  - Rule priority and execution ordering
         */
        class RuleBasedDetector
        {
        public:
            enum class RuleType
            {
                KEYWORD,      // Message contains specific text
                THRESHOLD,    // Event frequency exceeds limit
                LEVEL,        // Specific log level detected
                SOURCE,       // Specific source/service
                TIME_WINDOW,  // Events within time range
                SEQUENCE,     // Multi-event sequence match
                PATTERN,      // Advanced pattern matching
                COMPOSITE,    // Combination of multiple rules
                CUSTOM        // User-defined plugin rules
            };

            enum class RulePriority
            {
                CRITICAL = 0,
                HIGH = 1,
                MEDIUM = 2,
                LOW = 3
            };

            struct RuleConfig
            {
                std::string name;
                std::string id;           // Unique identifier for fast lookups
                RuleType type;
                RulePriority priority = RulePriority::MEDIUM;
                std::string condition;
                double severity = 0.8;
                bool enabled = true;
                std::size_t frequencyThreshold = 5;
                
                // Dynamic threshold adjustment
                bool adaptiveThreshold = false;
                double adaptiveMultiplier = 1.5;
                
                // Time window configuration
                std::chrono::seconds timeWindow{60};
                
                // Performance hints
                bool cacheable = true;
                std::size_t maxCacheSize = 1000;
                
                // Metadata for dynamic behavior
                std::unordered_map<std::string, std::string> metadata;
            };

            struct RuleMatch
            {
                std::string ruleName;
                std::string ruleId;
                RuleType ruleType;
                std::string details;
                double score;
                std::chrono::system_clock::time_point timestamp;
                std::unordered_map<std::string, std::string> context;
            };

            // Plugin interface for custom rules
            class IRulePlugin
            {
            public:
                virtual ~IRulePlugin() = default;
                virtual bool evaluate(const core::LogEntry& entry, 
                                    const RuleConfig& config) = 0;
                virtual std::string getPluginName() const = 0;
                virtual RuleType getPluginType() const = 0;
            };

            /// Constructor with optional config preloading
            explicit RuleBasedDetector(bool enableCaching = true, 
                                      std::size_t maxCacheEntries = 10000);

            // Non-copyable due to rule state tracking
            RuleBasedDetector(const RuleBasedDetector&) = delete;
            RuleBasedDetector& operator=(const RuleBasedDetector&) = delete;

            RuleBasedDetector(RuleBasedDetector&&) noexcept = default;
            RuleBasedDetector& operator=(RuleBasedDetector&&) noexcept = default;

            /**
             * Process single LogEntry against all active rules (optimized).
             * Uses read-write locks for better concurrency.
             * Thread-safe with minimal lock contention.
             */
            std::vector<RuleMatch> checkEntry(const core::LogEntry& entry);

            /**
             * Batch processing for better performance.
             * Processes multiple entries with shared lock acquisition.
             */
            std::vector<std::vector<RuleMatch>> checkEntries(
                const std::vector<core::LogEntry>& entries);

            /**
             * Load rules from configuration with hot-reload support.
             * Returns number of rules loaded/updated.
             */
            std::size_t loadRules(const Utils::ConfigLoader& config, 
                                 bool merge = false);

            /**
             * Hot-reload rules from file without stopping processing.
             */
            std::size_t reloadRules(const std::string& configPath);

            /**
             * Add custom rule with automatic compilation.
             */
            bool addRule(const RuleConfig& rule);

            /**
             * Remove rule by ID.
             */
            bool removeRule(const std::string& ruleId);

            /**
             * Update existing rule configuration.
             */
            bool updateRule(const std::string& ruleId, const RuleConfig& newConfig);

            /**
             * Get all currently loaded rules (thread-safe copy).
             */
            std::vector<RuleConfig> getRules() const;

            /**
             * Get rule by ID.
             */
            std::optional<RuleConfig> getRule(const std::string& ruleId) const;

            /**
             * Enable/disable specific rule by ID.
             */
            bool setRuleEnabled(const std::string& ruleId, bool enabled);

            /**
             * Register custom rule plugin for dynamic extensibility.
             */
            void registerPlugin(const std::string& pluginName, 
                              std::shared_ptr<IRulePlugin> plugin);

            /**
             * Unregister plugin.
             */
            void unregisterPlugin(const std::string& pluginName);

            /**
             * Convert rule matches to Anomaly reports.
             */
            std::vector<core::Anomaly> matchesToAnomalies(
                const std::vector<RuleMatch>& matches,
                const core::LogEntry& entry) const;

            /**
             * Get performance statistics.
             */
            struct Statistics
            {
                std::size_t totalChecks{0};
                std::size_t cacheHits{0};
                std::size_t cacheMisses{0};
                std::size_t ruleEvaluations{0};
                std::chrono::microseconds avgCheckTime{0};
                std::unordered_map<std::string, std::size_t> ruleMatchCounts;
            };

            Statistics getStatistics() const;
            void resetStatistics();

            /**
             * Clear internal caches and frequency counters.
             */
            void clearCaches();

            /**
             * Enable/disable adaptive thresholds globally.
             */
            void setAdaptiveThresholds(bool enabled);

        private:
            /// Rule execution function signature
            using RuleFunction = std::function<bool(const core::LogEntry&, RuleMatch&)>;

            /// Compiled rule with metadata
            struct CompiledRule
            {
                RuleConfig config;
                RuleFunction function;
                std::atomic<std::size_t> executionCount{0};
                std::atomic<std::size_t> matchCount{0};
                std::chrono::system_clock::time_point lastMatch;
                
                CompiledRule(RuleConfig cfg, RuleFunction func)
                    : config(std::move(cfg)), function(std::move(func))
                    , lastMatch(std::chrono::system_clock::now()) {}
            };

            /// Time-windowed event tracking with circular buffer
            struct TimeWindowTracker
            {
                std::deque<std::chrono::system_clock::time_point> events;
                std::mutex mutex;
                std::size_t maxSize;

                explicit TimeWindowTracker(std::size_t max = 1000) : maxSize(max) {}

                void addEvent(std::chrono::system_clock::time_point time);
                std::size_t countInWindow(std::chrono::seconds window);
                void cleanup(std::chrono::seconds window);
            };

            /// Parse and compile rule configuration
            RuleFunction compileRule(const RuleConfig& rule);

            /// Individual rule implementations (optimized)
            bool checkKeywordRule(const core::LogEntry& entry, 
                                const std::string& keywords,
                                RuleMatch& match) const;
            
            bool checkThresholdRule(const core::LogEntry& entry, 
                                  const RuleConfig& config,
                                  RuleMatch& match);
            
            bool checkLevelRule(const core::LogEntry& entry, 
                              core::LogLevel level,
                              RuleMatch& match) const;
            
            bool checkSourceRule(const core::LogEntry& entry, 
                               const std::string& source,
                               RuleMatch& match) const;
            
            bool checkTimeWindowRule(const core::LogEntry& entry,
                                   const RuleConfig& config,
                                   RuleMatch& match);
            
            bool checkSequenceRule(const core::LogEntry& entry,
                                 const RuleConfig& config,
                                 RuleMatch& match);
            
            bool checkPatternRule(const core::LogEntry& entry,
                                const std::string& pattern,
                                RuleMatch& match) const;
            
            bool checkCompositeRule(const core::LogEntry& entry,
                                  const RuleConfig& config,
                                  RuleMatch& match);

            /// Cache management
            struct CacheEntry
            {
                std::vector<RuleMatch> matches;
                std::chrono::system_clock::time_point timestamp;
            };

            std::optional<std::vector<RuleMatch>> checkCache(
                const core::LogEntry& entry) const;
            
            void updateCache(const core::LogEntry& entry, 
                           const std::vector<RuleMatch>& matches);

            /// Adaptive threshold calculation
            double calculateAdaptiveThreshold(const RuleConfig& rule) const;

            /// Sort rules by priority for execution order
            void sortRulesByPriority();

            /// Convert RuleType enum to string
            static std::string ruleTypeToString(RuleType type);
            static RuleType stringToRuleType(const std::string& str);

        private:
            // Thread-safe rule storage with read-write lock
            mutable std::shared_mutex m_rulesMutex;
            std::vector<std::shared_ptr<CompiledRule>> m_compiledRules;
            std::unordered_map<std::string, std::size_t> m_ruleIdIndex;

            // Frequency tracking with time windows
            std::unordered_map<std::string, std::unique_ptr<TimeWindowTracker>> m_timeTrackers;
            mutable std::shared_mutex m_trackersMutex;

            // Plugin system
            std::unordered_map<std::string, std::shared_ptr<IRulePlugin>> m_plugins;
            mutable std::shared_mutex m_pluginsMutex;

            // Cache system
            bool m_cachingEnabled;
            std::size_t m_maxCacheSize;
            mutable std::unordered_map<std::string, CacheEntry> m_cache;
            mutable std::shared_mutex m_cacheMutex;

            // Statistics (atomic for lock-free updates)
            mutable std::atomic<std::size_t> m_totalChecks{0};
            mutable std::atomic<std::size_t> m_cacheHits{0};
            mutable std::atomic<std::size_t> m_cacheMisses{0};
            mutable std::atomic<std::size_t> m_ruleEvaluations{0};

            // Configuration
            std::atomic<bool> m_adaptiveThresholdsEnabled{false};

            // Sequence tracking for sequence rules
            struct SequenceState
            {
                std::deque<core::LogEntry> events;
                std::size_t currentStep{0};
                std::chrono::system_clock::time_point startTime;
            };
            std::unordered_map<std::string, SequenceState> m_sequenceStates;
            mutable std::mutex m_sequenceMutex;
        };

    } // namespace Anomaly
} // namespace LogTool