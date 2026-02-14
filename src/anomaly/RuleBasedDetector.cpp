#include "anomaly/RuleBasedDetector.hpp"

#include <algorithm>
#include <sstream>
#include <cctype>
#include <utility>

#include "utils/StringUtils.hpp"
#include "utils/Logger.hpp"

namespace LogTool::Anomaly
{
    // ---------- small helpers ----------
    static std::string optToString(const std::optional<std::string>& v)
    {
        return v.value_or(std::string{});
    }

    static std::string makeCacheKey(const core::LogEntry& entry)
    {
        // source() is optional<string> in your core::LogEntry (based on your error)
        // message() is a function (based on your earlier error)
        return optToString(entry.source()) + "|" + entry.message();
    }

    static std::string trimLeft(std::string s)
    {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
            s.erase(s.begin());
        return s;
    }

    // Try to parse LEVEL rules without knowing core::LogLevel enum values:
    // - If condition is numeric, interpret as enum underlying value.
    // - Otherwise: cannot map string -> enum reliably without LogLevel helpers,
    //   so we return std::nullopt and that LEVEL rule becomes "never match".
    static std::optional<core::LogLevel> parseLogLevelLoose(const std::string& condition)
    {
        std::string s = LogTool::Utils::toUpper(condition);
        s = trimLeft(std::move(s));

        // numeric?
        bool allDigits = !s.empty();
        for (char c : s)
        {
            if (!std::isdigit(static_cast<unsigned char>(c)))
            {
                allDigits = false;
                break;
            }
        }

        if (allDigits)
        {
            try
            {
                int v = std::stoi(s);
                return static_cast<core::LogLevel>(v);
            }
            catch (...)
            {
                return std::nullopt;
            }
        }

        // Unknown named levels because your enum doesn't have INFO/ERROR/WARN/CRITICAL.
        return std::nullopt;
    }

    // ---------- TimeWindowTracker ----------
    void RuleBasedDetector::TimeWindowTracker::addEvent(std::chrono::system_clock::time_point time)
    {
        std::lock_guard<std::mutex> lock(mutex);
        events.push_back(time);
        if (events.size() > maxSize)
            events.pop_front();
    }

    void RuleBasedDetector::TimeWindowTracker::cleanup(std::chrono::seconds window)
    {
        const auto now = std::chrono::system_clock::now();
        const auto cutoff = now - window;
        while (!events.empty() && events.front() < cutoff)
            events.pop_front();
    }

    std::size_t RuleBasedDetector::TimeWindowTracker::countInWindow(std::chrono::seconds window)
    {
        std::lock_guard<std::mutex> lock(mutex);
        cleanup(window);
        return events.size();
    }

    // ---------- ctor ----------
    RuleBasedDetector::RuleBasedDetector(bool enableCaching, std::size_t maxCacheEntries)
        : m_cachingEnabled(enableCaching),
          m_maxCacheSize(maxCacheEntries)
    {
        // Keep defaults conservative and not dependent on core::LogLevel enumerator names.
        // KEYWORD rules compile fine.
        RuleConfig r1;
        r1.name = "error_keyword";
        r1.id = "error_keyword";
        r1.type = RuleType::KEYWORD;
        r1.priority = RulePriority::HIGH;
        r1.condition = "ERROR";
        r1.severity = 0.9;
        addRule(r1);

        RuleConfig r2;
        r2.name = "critical_keyword";
        r2.id = "critical_keyword";
        r2.type = RuleType::KEYWORD;
        r2.priority = RulePriority::CRITICAL;
        r2.condition = "CRITICAL";
        r2.severity = 1.0;
        addRule(r2);

        Utils::getLogger().info("RuleBasedDetector initialized");
    }

    // ---------- cache ----------
    std::optional<std::vector<RuleBasedDetector::RuleMatch>>
    RuleBasedDetector::checkCache(const core::LogEntry& entry) const
    {
        if (!m_cachingEnabled) return std::nullopt;

        const std::string key = makeCacheKey(entry);

        std::shared_lock<std::shared_mutex> lock(m_cacheMutex);
        auto it = m_cache.find(key);
        if (it == m_cache.end())
            return std::nullopt;

        m_cacheHits.fetch_add(1, std::memory_order_relaxed);
        return it->second.matches;
    }

    void RuleBasedDetector::updateCache(const core::LogEntry& entry,
                                        const std::vector<RuleMatch>& matches)
    {
        if (!m_cachingEnabled) return;

        const std::string key = makeCacheKey(entry);

        std::unique_lock<std::shared_mutex> lock(m_cacheMutex);

        if (m_cache.size() >= m_maxCacheSize && !m_cache.empty())
            m_cache.erase(m_cache.begin());

        CacheEntry ce;
        ce.matches = matches;
        ce.timestamp = std::chrono::system_clock::now();
        m_cache[key] = std::move(ce);
    }

    void RuleBasedDetector::clearCaches()
    {
        {
            std::unique_lock<std::shared_mutex> lock(m_cacheMutex);
            m_cache.clear();
        }
        {
            std::unique_lock<std::shared_mutex> lock(m_trackersMutex);
            m_timeTrackers.clear();
        }
        {
            std::lock_guard<std::mutex> lock(m_sequenceMutex);
            m_sequenceStates.clear();
        }
        resetStatistics();
    }

    // ---------- stats ----------
    RuleBasedDetector::Statistics RuleBasedDetector::getStatistics() const
    {
        Statistics s;
        s.totalChecks = m_totalChecks.load(std::memory_order_relaxed);
        s.cacheHits = m_cacheHits.load(std::memory_order_relaxed);
        s.cacheMisses = m_cacheMisses.load(std::memory_order_relaxed);
        s.ruleEvaluations = m_ruleEvaluations.load(std::memory_order_relaxed);

        std::shared_lock<std::shared_mutex> lock(m_rulesMutex);
        for (const auto& cr : m_compiledRules)
        {
            if (!cr) continue;
            s.ruleMatchCounts[cr->config.id] = cr->matchCount.load(std::memory_order_relaxed);
        }
        return s;
    }

    void RuleBasedDetector::resetStatistics()
    {
        m_totalChecks.store(0, std::memory_order_relaxed);
        m_cacheHits.store(0, std::memory_order_relaxed);
        m_cacheMisses.store(0, std::memory_order_relaxed);
        m_ruleEvaluations.store(0, std::memory_order_relaxed);
    }

    void RuleBasedDetector::setAdaptiveThresholds(bool enabled)
    {
        m_adaptiveThresholdsEnabled.store(enabled, std::memory_order_relaxed);
    }

    // ---------- rule compilation ----------
    RuleBasedDetector::RuleFunction RuleBasedDetector::compileRule(const RuleConfig& rule)
    {
        switch (rule.type)
        {
            case RuleType::KEYWORD:
                return [this, rule](const core::LogEntry& e, RuleMatch& m) {
                    return checkKeywordRule(e, rule.condition, m);
                };

            case RuleType::SOURCE:
                return [this, rule](const core::LogEntry& e, RuleMatch& m) {
                    return checkSourceRule(e, rule.condition, m);
                };

            case RuleType::THRESHOLD:
                return [this, rule](const core::LogEntry& e, RuleMatch& m) {
                    return checkThresholdRule(e, rule, m);
                };

            case RuleType::TIME_WINDOW:
                return [this, rule](const core::LogEntry& e, RuleMatch& m) {
                    return checkTimeWindowRule(e, rule, m);
                };

            case RuleType::SEQUENCE:
                return [this, rule](const core::LogEntry& e, RuleMatch& m) {
                    return checkSequenceRule(e, rule, m);
                };

            case RuleType::PATTERN:
                return [this, rule](const core::LogEntry& e, RuleMatch& m) {
                    return checkPatternRule(e, rule.condition, m);
                };

            case RuleType::COMPOSITE:
                return [this, rule](const core::LogEntry& e, RuleMatch& m) {
                    return checkCompositeRule(e, rule, m);
                };

            case RuleType::CUSTOM:
                return [this, rule](const core::LogEntry& e, RuleMatch& m) {
                    std::shared_lock<std::shared_mutex> plock(m_pluginsMutex);
                    for (const auto& kv : m_plugins)
                    {
                        if (!kv.second) continue;
                        if (kv.second->getPluginType() != RuleType::CUSTOM) continue;

                        if (kv.second->evaluate(e, rule))
                        {
                            m.ruleName = rule.name;
                            m.ruleId = rule.id;
                            m.ruleType = rule.type;
                            m.details = "CUSTOM plugin triggered: " + kv.second->getPluginName();
                            m.score = rule.severity;
                            m.timestamp = std::chrono::system_clock::now();
                            return true;
                        }
                    }
                    return false;
                };

            case RuleType::LEVEL:
            {
                // We cannot assume enum member names exist.
                // Try numeric level matching if user supplies "0", "1", etc.
                const auto lvlOpt = parseLogLevelLoose(rule.condition);
                if (!lvlOpt)
                {
                    return [](const core::LogEntry&, RuleMatch&) { return false; };
                }

                const core::LogLevel lvl = *lvlOpt;
                return [this, lvl, rule](const core::LogEntry& e, RuleMatch& m) {
                    return checkLevelRule(e, lvl, m);
                };
            }
        }

        return [](const core::LogEntry&, RuleMatch&) { return false; };
    }

    void RuleBasedDetector::sortRulesByPriority()
    {
        std::sort(m_compiledRules.begin(), m_compiledRules.end(),
                  [](const std::shared_ptr<CompiledRule>& a,
                     const std::shared_ptr<CompiledRule>& b) {
                      if (!a) return false;
                      if (!b) return true;
                      return static_cast<int>(a->config.priority) < static_cast<int>(b->config.priority);
                  });
    }

    double RuleBasedDetector::calculateAdaptiveThreshold(const RuleConfig& rule) const
    {
        if (!rule.adaptiveThreshold)
            return static_cast<double>(rule.frequencyThreshold);
        return static_cast<double>(rule.frequencyThreshold) * rule.adaptiveMultiplier;
    }

    // ---------- public: check ----------
    std::vector<RuleBasedDetector::RuleMatch>
    RuleBasedDetector::checkEntry(const core::LogEntry& entry)
    {
        m_totalChecks.fetch_add(1, std::memory_order_relaxed);

        if (auto cached = checkCache(entry))
            return *cached;

        m_cacheMisses.fetch_add(1, std::memory_order_relaxed);

        std::vector<RuleMatch> matches;

        std::shared_lock<std::shared_mutex> lock(m_rulesMutex);

        for (const auto& cr : m_compiledRules)
        {
            if (!cr) continue;
            if (!cr->config.enabled) continue;

            m_ruleEvaluations.fetch_add(1, std::memory_order_relaxed);
            cr->executionCount.fetch_add(1, std::memory_order_relaxed);

            RuleMatch match{};
            if (cr->function(entry, match))
            {
                if (match.ruleId.empty()) match.ruleId = cr->config.id;
                if (match.ruleName.empty()) match.ruleName = cr->config.name;
                match.ruleType = cr->config.type;
                if (match.score <= 0.0) match.score = cr->config.severity;
                if (match.timestamp.time_since_epoch().count() == 0)
                    match.timestamp = std::chrono::system_clock::now();

                cr->matchCount.fetch_add(1, std::memory_order_relaxed);
                cr->lastMatch = match.timestamp;

                matches.push_back(std::move(match));
            }
        }

        updateCache(entry, matches);
        return matches;
    }

    std::vector<std::vector<RuleBasedDetector::RuleMatch>>
    RuleBasedDetector::checkEntries(const std::vector<core::LogEntry>& entries)
    {
        std::vector<std::vector<RuleMatch>> out;
        out.reserve(entries.size());
        for (const auto& e : entries)
            out.push_back(checkEntry(e));
        return out;
    }

    // ---------- loading rules ----------
    std::size_t RuleBasedDetector::loadRules(const Utils::ConfigLoader& config, bool merge)
    {
        std::unique_lock<std::shared_mutex> lock(m_rulesMutex);

        if (!merge)
        {
            m_compiledRules.clear();
            m_ruleIdIndex.clear();
        }

        std::size_t loaded = 0;

        for (const auto& kv : config.all())
        {
            const std::string& key = kv.first;
            const std::string& value = kv.second;

            if (!Utils::startsWith(key, "rule."))
                continue;

            std::istringstream iss(value);

            RuleConfig rc;
            iss >> rc.name;

            std::string typeStr;
            iss >> typeStr;

            std::string cond;
            std::getline(iss, cond);
            rc.condition = trimLeft(std::move(cond));

            rc.type = stringToRuleType(typeStr);
            rc.id = key; // default id from key; user can override in config if they want
            rc.enabled = config.getBoolOr(key + ".enabled", true);

            if (auto sev = config.getDouble(key + ".severity"))
                rc.severity = std::clamp(*sev, 0.0, 1.0);

            // addRule locks again; to avoid deadlock, call internal insertion here:
            // We'll temporarily unlock, call addRule, then relock (simple + safe).
            lock.unlock();
            if (addRule(rc)) ++loaded;
            lock.lock();
        }

        sortRulesByPriority();
        return loaded;
    }

    std::size_t RuleBasedDetector::reloadRules(const std::string& configPath)
    {
        Utils::ConfigLoader loader;
        if (!loader.loadFromFile(configPath))
            return 0;
        return loadRules(loader, false);
    }

    // ---------- rule management ----------
    bool RuleBasedDetector::addRule(const RuleConfig& rule)
    {
        RuleConfig cfg = rule;
        if (cfg.id.empty())
            cfg.id = cfg.name;

        std::unique_lock<std::shared_mutex> lock(m_rulesMutex);

        auto it = m_ruleIdIndex.find(cfg.id);
        if (it != m_ruleIdIndex.end())
        {
            // Update existing
            const std::size_t idx = it->second;
            if (idx >= m_compiledRules.size() || !m_compiledRules[idx])
                return false;

            m_compiledRules[idx]->config = cfg;
            m_compiledRules[idx]->function = compileRule(cfg);
            return true;
        }

        auto func = compileRule(cfg);
        auto compiled = std::make_shared<CompiledRule>(cfg, std::move(func));

        m_ruleIdIndex[cfg.id] = m_compiledRules.size();
        m_compiledRules.push_back(std::move(compiled));

        // Initialize tracker for threshold rules
        if (cfg.type == RuleType::THRESHOLD)
        {
            std::unique_lock<std::shared_mutex> tlock(m_trackersMutex);
            if (m_timeTrackers.find(cfg.id) == m_timeTrackers.end())
                m_timeTrackers[cfg.id] = std::make_unique<TimeWindowTracker>(cfg.maxCacheSize);
        }

        sortRulesByPriority();
        return true;
    }

    bool RuleBasedDetector::removeRule(const std::string& ruleId)
    {
        std::unique_lock<std::shared_mutex> lock(m_rulesMutex);

        auto it = m_ruleIdIndex.find(ruleId);
        if (it == m_ruleIdIndex.end())
            return false;

        const std::size_t idx = it->second;
        if (idx >= m_compiledRules.size())
            return false;

        m_compiledRules.erase(m_compiledRules.begin() + static_cast<std::ptrdiff_t>(idx));
        m_ruleIdIndex.erase(it);

        // rebuild index
        m_ruleIdIndex.clear();
        for (std::size_t i = 0; i < m_compiledRules.size(); ++i)
        {
            if (m_compiledRules[i])
                m_ruleIdIndex[m_compiledRules[i]->config.id] = i;
        }

        // remove tracker
        {
            std::unique_lock<std::shared_mutex> tlock(m_trackersMutex);
            m_timeTrackers.erase(ruleId);
        }

        return true;
    }

    bool RuleBasedDetector::updateRule(const std::string& ruleId, const RuleConfig& newConfig)
    {
        RuleConfig cfg = newConfig;
        cfg.id = ruleId;

        std::unique_lock<std::shared_mutex> lock(m_rulesMutex);

        auto it = m_ruleIdIndex.find(ruleId);
        if (it == m_ruleIdIndex.end())
            return false;

        auto& cr = m_compiledRules[it->second];
        if (!cr) return false;

        cr->config = cfg;
        cr->function = compileRule(cfg);
        sortRulesByPriority();
        return true;
    }

    std::vector<RuleBasedDetector::RuleConfig> RuleBasedDetector::getRules() const
    {
        std::shared_lock<std::shared_mutex> lock(m_rulesMutex);
        std::vector<RuleConfig> out;
        out.reserve(m_compiledRules.size());
        for (const auto& cr : m_compiledRules)
            if (cr) out.push_back(cr->config);
        return out;
    }

    std::optional<RuleBasedDetector::RuleConfig> RuleBasedDetector::getRule(const std::string& ruleId) const
    {
        std::shared_lock<std::shared_mutex> lock(m_rulesMutex);
        auto it = m_ruleIdIndex.find(ruleId);
        if (it == m_ruleIdIndex.end())
            return std::nullopt;

        const auto& cr = m_compiledRules[it->second];
        if (!cr) return std::nullopt;
        return cr->config;
    }

    bool RuleBasedDetector::setRuleEnabled(const std::string& ruleId, bool enabled)
    {
        std::unique_lock<std::shared_mutex> lock(m_rulesMutex);
        auto it = m_ruleIdIndex.find(ruleId);
        if (it == m_ruleIdIndex.end())
            return false;
        auto& cr = m_compiledRules[it->second];
        if (!cr) return false;
        cr->config.enabled = enabled;
        return true;
    }

    // ---------- plugins ----------
    void RuleBasedDetector::registerPlugin(const std::string& pluginName,
                                          std::shared_ptr<IRulePlugin> plugin)
    {
        std::unique_lock<std::shared_mutex> lock(m_pluginsMutex);
        m_plugins[pluginName] = std::move(plugin);
    }

    void RuleBasedDetector::unregisterPlugin(const std::string& pluginName)
    {
        std::unique_lock<std::shared_mutex> lock(m_pluginsMutex);
        m_plugins.erase(pluginName);
    }

    // ---------- rule checks ----------
    bool RuleBasedDetector::checkKeywordRule(const core::LogEntry& entry,
                                             const std::string& keywords,
                                             RuleMatch& match) const
    {
        const std::string msgUp = Utils::toUpper(entry.message());
        const std::string kwUp  = Utils::toUpper(keywords);

        if (!Utils::contains(msgUp, kwUp))
            return false;

        match.details = "KEYWORD match: " + keywords;
        return true;
    }

    bool RuleBasedDetector::checkLevelRule(const core::LogEntry& entry,
                                           core::LogLevel level,
                                           RuleMatch& match) const
    {
        if (entry.level() != level)
            return false;

        match.details = "LEVEL match";
        return true;
    }

    bool RuleBasedDetector::checkSourceRule(const core::LogEntry& entry,
                                            const std::string& source,
                                            RuleMatch& match) const
    {
        // entry.source() is optional<string>
        const std::string src = optToString(entry.source());
        if (src.empty())
            return false;

        if (!Utils::iequals(src, source))
            return false;

        match.details = "SOURCE match: " + source;
        return true;
    }

    bool RuleBasedDetector::checkThresholdRule(const core::LogEntry&,
                                               const RuleConfig& config,
                                               RuleMatch& match)
    {
        // Ensure tracker exists
        {
            std::unique_lock<std::shared_mutex> lock(m_trackersMutex);
            if (m_timeTrackers.find(config.id) == m_timeTrackers.end())
                m_timeTrackers[config.id] = std::make_unique<TimeWindowTracker>(config.maxCacheSize);
        }

        // Record event + count window
        std::size_t count = 0;
        {
            std::shared_lock<std::shared_mutex> lock(m_trackersMutex);
            auto it = m_timeTrackers.find(config.id);
            if (it == m_timeTrackers.end() || !it->second)
                return false;

            it->second->addEvent(std::chrono::system_clock::now());
            count = it->second->countInWindow(config.timeWindow);
        }

        std::size_t threshold = config.frequencyThreshold;
        if (m_adaptiveThresholdsEnabled.load(std::memory_order_relaxed))
            threshold = static_cast<std::size_t>(calculateAdaptiveThreshold(config));

        if (count < threshold)
            return false;

        std::ostringstream oss;
        oss << "THRESHOLD exceeded: " << count << " in "
            << config.timeWindow.count() << "s (threshold=" << threshold << ")";
        match.details = oss.str();
        return true;
    }

    bool RuleBasedDetector::checkTimeWindowRule(const core::LogEntry&,
                                                const RuleConfig&,
                                                RuleMatch&)
    {
        // Not implemented (placeholder)
        return false;
    }

    bool RuleBasedDetector::checkSequenceRule(const core::LogEntry&,
                                              const RuleConfig&,
                                              RuleMatch&)
    {
        // Not implemented (placeholder)
        return false;
    }

    bool RuleBasedDetector::checkPatternRule(const core::LogEntry&,
                                             const std::string&,
                                             RuleMatch&) const
    {
        // Not implemented (placeholder)
        return false;
    }

    bool RuleBasedDetector::checkCompositeRule(const core::LogEntry&,
                                               const RuleConfig&,
                                               RuleMatch&)
    {
        // Not implemented (placeholder)
        return false;
    }

    // ---------- anomalies ----------
    std::vector<core::Anomaly>
    RuleBasedDetector::matchesToAnomalies(const std::vector<RuleMatch>&,
                                          const core::LogEntry&) const
    {
        // Safe placeholder: avoid assuming core::Anomaly setters/fields.
        return {};
    }

    // ---------- enum conversions ----------
    std::string RuleBasedDetector::ruleTypeToString(RuleType type)
    {
        switch (type)
        {
            case RuleType::KEYWORD: return "KEYWORD";
            case RuleType::THRESHOLD: return "THRESHOLD";
            case RuleType::LEVEL: return "LEVEL";
            case RuleType::SOURCE: return "SOURCE";
            case RuleType::TIME_WINDOW: return "TIME_WINDOW";
            case RuleType::SEQUENCE: return "SEQUENCE";
            case RuleType::PATTERN: return "PATTERN";
            case RuleType::COMPOSITE: return "COMPOSITE";
            case RuleType::CUSTOM: return "CUSTOM";
            default: return "UNKNOWN";
        }
    }

    RuleBasedDetector::RuleType RuleBasedDetector::stringToRuleType(const std::string& str)
    {
        const std::string up = Utils::toUpper(str);
        if (up == "KEYWORD") return RuleType::KEYWORD;
        if (up == "THRESHOLD") return RuleType::THRESHOLD;
        if (up == "LEVEL") return RuleType::LEVEL;
        if (up == "SOURCE") return RuleType::SOURCE;
        if (up == "TIME_WINDOW") return RuleType::TIME_WINDOW;
        if (up == "SEQUENCE") return RuleType::SEQUENCE;
        if (up == "PATTERN") return RuleType::PATTERN;
        if (up == "COMPOSITE") return RuleType::COMPOSITE;
        if (up == "CUSTOM") return RuleType::CUSTOM;
        return RuleType::KEYWORD;
    }

} // namespace LogTool::Anomaly