#include "input/LogParser.hpp"
#include "utils/Utils.hpp"   // Utils::trim/ltrim/rtrim/split/contains/toUpper/parseTimestamp

#include <regex>
#include <algorithm>
#include <vector>

#include <cctype>
#include <sstream>

#include <ctime>
namespace LogTool
{
    namespace Input
    {
        using namespace Core;   // Uses alias from your header: LogTool::Core -> LogTool::core
        using namespace Utils;

        
        namespace
        {
            inline bool isReasonableTime(const Core::LogEntry::TimePoint& tp)
            {
                using Clock = Core::LogEntry::Clock;
                const auto t = Clock::to_time_t(tp);
                // Reject epoch/very old dates (before 2000-01-01)
                return t >= 946684800; // 2000-01-01 00:00:00 UTC
            }

            inline Core::LogEntry::TimePoint fallbackNow()
            {
                return Core::LogEntry::Clock::now();
            }
        } // anonymous namespace

LogParser::LogParser()
        {
            // Pre-configure common log patterns the parser will try
            m_patterns = {
                // Apache/Nginx style: [timestamp] level source: message
                "%timestamp% %level% %source%: %message%",
                // Syslog style: timestamp level source message
                "%timestamp% %level% %source% %message%",
                // Custom bracketed: [timestamp] level[source] message
                "\\[%timestamp%] %level%\\[%source%] %message%",
                // Simple timestamp level message
                "%timestamp% %level% %message%"
            };
        }

        std::optional<Core::LogEntry> LogParser::parseLine(std::string_view rawLine) const
        {
            auto r = parseLineDetailed(rawLine);
            return r.entry;
        }

        LogParser::ParseResult LogParser::parseLineDetailed(std::string_view rawLine) const
        {
            ParseResult r;

            const auto trimmed = trimSv(rawLine);
            if (trimmed.empty())
            {
                r.malformed = true;
                r.error = "Empty line";
                return r;
            }

            // JSON line? (mixed JSON + text logs)
            if (!trimmed.empty() && trimmed.front() == '{')
            {
                r.wasJson = true;
                std::string err;
                auto e = tryParseJsonLine(trimmed, &err);
                if (e)
                {
                    r.entry = std::move(e);
                    return r;
                }
                r.malformed = true;
                r.error = err.empty() ? "Failed to parse JSON log line" : err;
                return r;
            }

            for (const auto &pattern : m_patterns)
            {
                auto entry = tryParsePattern(trimmed, pattern);
                if (entry)
                {
                    r.entry = std::move(entry);
                    return r;
                }
            }

            r.malformed = true;
            r.error = "No matching pattern";
            return r;
        }

        std::optional<Core::LogEntry> LogParser::parseNext(FileReader &reader) const
        {
            auto lineOpt = reader.nextLine();
            if (!lineOpt)
            {
                return std::nullopt;
            }
            return parseLine(*lineOpt);
        }

        void LogParser::addPattern(std::string pattern)
        {
            m_patterns.push_back(std::move(pattern));
        }

        void LogParser::clearPatterns()
        {
            m_patterns.clear();
        }

        const std::vector<std::string> &LogParser::patterns() const noexcept
        {
            return m_patterns;
        }

        std::optional<Core::LogEntry> LogParser::tryParsePattern(
            std::string_view line,
            std::string_view /*pattern*/) const
        {
            // Heuristic parsing (robust to format differences)
            auto timestamp = extractTimestamp(line);
            auto level     = extractLevel(line);
            auto source    = extractSource(line);
            auto message   = extractMessage(line);

            if (!timestamp || !level || !message)
            {
                return std::nullopt;
            }

            // NOTE: This constructor call must match your Core::LogEntry API from include/core/LogEntry.hpp.
            // If your LogEntry uses a different constructor/setters, adjust here accordingly.
            return Core::LogEntry(timestamp.value(),
                                  level.value(),
                                  source.value_or("unknown"),
                                  std::move(*message),
                                  std::string(line));
        }

        // -------------------------
        // JSON parsing (best-effort, no external dependency)
        // -------------------------
        std::optional<Core::LogEntry> LogParser::tryParseJsonLine(std::string_view line, std::string* errOut) const
        {
            // Expected keys (flexible): timestamp/time/@timestamp, level/severity, service/component/source, message/msg
            auto tsStr = extractJsonString(line, "timestamp");
            if (!tsStr) tsStr = extractJsonString(line, "time");
            if (!tsStr) tsStr = extractJsonString(line, "@timestamp");

            auto lvlStr = extractJsonString(line, "level");
            if (!lvlStr) lvlStr = extractJsonString(line, "severity");

            auto msgStr = extractJsonString(line, "message");
            if (!msgStr) msgStr = extractJsonString(line, "msg");

            auto srcStr = extractJsonString(line, "service");
            if (!srcStr) srcStr = extractJsonString(line, "component");
            if (!srcStr) srcStr = extractJsonString(line, "source");

            if (!tsStr || !lvlStr || !msgStr)
            {
                if (errOut)
                {
                    std::ostringstream oss;
                    oss << "JSON missing required fields:"
                        << (tsStr ? "" : " timestamp")
                        << (lvlStr ? "" : " level")
                        << (msgStr ? "" : " message");
                    *errOut = oss.str();
                }
                return std::nullopt;
            }

            // Timestamp: accept either ISO-8601 or "YYYY-MM-DD HH:MM:SS" prefix
            Utils::TimePoint ts;
            bool okTs = false;
            {
                std::string_view tsv(*tsStr);
                // try first 19 chars if contains space format
                if (tsv.size() >= 19)
                {
                    if (auto p = Utils::parseTimestamp(tsv.substr(0, 19)))
                    {
                        ts = *p;
                        okTs = true;
                    }
                }
                if (!okTs)
                {
                    // Try ISO: "YYYY-MM-DDTHH:MM:SS" (use first 19, replace 'T' with ' ')
                    if (tsv.size() >= 19)
                    {
                        std::string tmp(tsv.substr(0, 19));
                        for (char& c : tmp) if (c == 'T') c = ' ';
                        if (auto p = Utils::parseTimestamp(std::string_view(tmp)))
                        {
                            ts = *p;
                            okTs = true;
                        }
                    }
                }
            }
            if (!okTs)
            {
                if (errOut) *errOut = "Invalid timestamp format";
                return std::nullopt;
            }

            // Level mapping
            const std::string upperLvl = Utils::toUpper(*lvlStr);
            Core::LogLevel lvl = Core::LogLevel::Unknown;
            if (upperLvl.find("TRACE") != std::string::npos) lvl = Core::LogLevel::Trace;
            else if (upperLvl.find("DEBUG") != std::string::npos) lvl = Core::LogLevel::Debug;
            else if (upperLvl.find("INFO") != std::string::npos) lvl = Core::LogLevel::Info;
            else if (upperLvl.find("WARN") != std::string::npos) lvl = Core::LogLevel::Warn;
            else if (upperLvl.find("ERROR") != std::string::npos) lvl = Core::LogLevel::Error;
            else if (upperLvl.find("CRIT") != std::string::npos || upperLvl.find("FATAL") != std::string::npos) lvl = Core::LogLevel::Critical;

            return Core::LogEntry(ts, lvl, srcStr ? std::optional<std::string>(*srcStr) : std::optional<std::string>("unknown"), *msgStr, std::string(line));
        }

        std::string_view LogParser::trimSv(std::string_view s)
        {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
            return s;
        }

        std::optional<std::string> LogParser::extractJsonRaw(std::string_view json, std::string_view key)
        {
            // Find "key" : ... (very small best-effort parser)
            const std::string needle = std::string("\"") + std::string(key) + "\"";
            auto pos = json.find(needle);
            if (pos == std::string_view::npos) return std::nullopt;
            pos = json.find(':', pos + needle.size());
            if (pos == std::string_view::npos) return std::nullopt;
            ++pos;
            while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
            if (pos >= json.size()) return std::nullopt;

            // If string value
            if (json[pos] == '"')
            {
                ++pos;
                std::string out;
                while (pos < json.size())
                {
                    const char c = json[pos++];
                    if (c == '\\')
                    {
                        if (pos < json.size())
                        {
                            // basic escape handling
                            out.push_back(json[pos++]);
                        }
                        continue;
                    }
                    if (c == '"') break;
                    out.push_back(c);
                }
                return out;
            }

            // Non-string: read until comma or end brace
            std::size_t end = pos;
            while (end < json.size() && json[end] != ',' && json[end] != '}') ++end;
            std::string out(json.substr(pos, end - pos));
            // trim
            std::string_view sv(out);
            sv = trimSv(sv);
            return std::string(sv);
        }

        std::optional<std::string> LogParser::extractJsonString(std::string_view json, std::string_view key)
        {
            return extractJsonRaw(json, key);
        }

        std::optional<Utils::TimePoint> LogParser::extractTimestamp(std::string_view line) const
        {
            std::string_view prefix = Utils::ltrim(line);
            if (prefix.size() < 19)
            {
                return std::nullopt;
            }

            // Try "YYYY-MM-DD HH:MM:SS" at start (first 19 chars)
            if (auto tp = Utils::parseTimestamp(prefix.substr(0, 19)))
            {
                return tp;
            }

            // TODO: add more formats if needed
            return std::nullopt;
        }

        std::optional<Core::LogLevel> LogParser::extractLevel(std::string_view line) const
        {
            // FIXED: enum values match include/core/LogEntry.hpp:
            // Trace, Debug, Info, Warn, Error, Critical, Unknown
            static const struct
            {
                std::string_view levelStr;
                Core::LogLevel level;
            } levelMap[] = {
                {"TRACE",    Core::LogLevel::Trace},
                {"DEBUG",    Core::LogLevel::Debug},
                {"INFO",     Core::LogLevel::Info},
                {"WARN",     Core::LogLevel::Warn},
                {"WARNING",  Core::LogLevel::Warn},
                {"ERROR",    Core::LogLevel::Error},
                {"FATAL",    Core::LogLevel::Critical},
                {"CRITICAL", Core::LogLevel::Critical},
            };

            // IMPORTANT: Utils::toUpper likely returns std::string.
            // Keep it alive to avoid dangling references.
            const std::string upperLine = Utils::toUpper(line);

            for (const auto &mapping : levelMap)
            {
                if (Utils::contains(upperLine, mapping.levelStr))
                {
                    return mapping.level;
                }
            }

            return Core::LogLevel::Unknown; // default if not detected
        }

        std::optional<std::string> LogParser::extractSource(std::string_view line) const
        {
            std::string_view trimmed = Utils::trim(line);

            // Pattern 1: source: message
            auto colonPos = trimmed.find(':');
            if (colonPos != std::string_view::npos)
            {
                std::string_view potentialSource = Utils::rtrim(trimmed.substr(0, colonPos));
                if (potentialSource.find(' ') == std::string_view::npos)
                {
                    return std::string(potentialSource);
                }
            }

            // Pattern 2: [source]
            if (auto start = trimmed.find('['); start != std::string_view::npos)
            {
                auto end = trimmed.find(']', start);
                if (end != std::string_view::npos)
                {
                    return std::string(trimmed.substr(start + 1, end - start - 1));
                }
            }

            return std::nullopt;
        }

        std::optional<std::string> LogParser::extractMessage(std::string_view line) const
        {
            std::string message;

            // Skip timestamp prefix (first ~20 chars)
            std::string_view remaining = Utils::trim(line);
            if (remaining.size() > 20)
            {
                remaining.remove_prefix(20);
            }

            // Skip level + maybe source
            remaining = Utils::trim(remaining);
            std::vector<std::string_view> words = Utils::split(remaining, ' ', true);

            if (words.size() > 2)
            {
                message.reserve(remaining.size());
                for (std::size_t i = 2; i < words.size(); ++i)
                {
                    if (i > 2) message += ' ';
                    message.append(words[i]);
                }
            }

            if (message.empty())
            {
                return std::nullopt;
            }

            return message; // NRVO/move
        }

    } // namespace Input
} // namespace LogTool
