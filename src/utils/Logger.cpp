#include "utils/Logger.hpp"

#include <iostream>
#include <chrono>

namespace LogTool
{
    namespace Utils
    {
        // ------------ Logger implementation ------------

        Logger::Logger()
            : m_level(LogLevel::INFO),
              m_file(),
              m_fileEnabled(false),
              m_console(&std::cerr)
        {
            // Default: only console logging (stderr).
        }

        Logger::Logger(std::string_view filePath, LogLevel level)
            : m_level(level),
              m_file(),
              m_fileEnabled(false),
              m_console(&std::cerr)
        {
            if (!filePath.empty())
            {
                // Open file in append mode; RAII will close it in the destructor.
                m_file.open(std::string(filePath), std::ios::out | std::ios::app);
                if (m_file.is_open())
                {
                    m_fileEnabled = true;
                }
            }
        }

        Logger::Logger(Logger &&other) noexcept
            : m_level(other.m_level),
              m_file(),          // will reopen if needed
              m_fileEnabled(other.m_fileEnabled),
              m_console(other.m_console)
        {
            // Move constructor: we cannot move std::ofstream portably, so if the
            // source had file logging enabled, we reopen the file by stealing
            // its rdbuf if possible (or just rely on console if that fails).
            if (other.m_fileEnabled && other.m_file.is_open())
            {
                // Try to steal the filebuf (implementation-defined but common),
                // otherwise fall back to console-only.
                m_file.basic_ios<char>::rdbuf(other.m_file.rdbuf());
            }
            other.m_fileEnabled = false;
        }

        Logger &Logger::operator=(Logger &&other) noexcept
        {
            if (this != &other)
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_level       = other.m_level;
                m_console     = other.m_console;
                m_fileEnabled = other.m_fileEnabled;

                if (m_file.is_open())
                {
                    m_file.close();
                }

                if (other.m_fileEnabled && other.m_file.is_open())
                {
                    m_file.basic_ios<char>::rdbuf(other.m_file.rdbuf());
                }
                else
                {
                    m_fileEnabled = false;
                }

                other.m_fileEnabled = false;
            }
            return *this;
        }

        Logger::~Logger()
        {
            // RAII: ensure file is closed on destruction.
            if (m_file.is_open())
            {
                m_file.flush();
                m_file.close();
            }
        }

        void Logger::setLevel(LogLevel level) noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_level = level;
        }

        LogLevel Logger::level() const noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_level;
        }

        bool Logger::isEnabled(LogLevel level) const noexcept
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return static_cast<int>(level) >= static_cast<int>(m_level);
        }

        void Logger::log(LogLevel level, std::string_view message)
        {
            // Fast path: check level without holding the lock unnecessarily long.
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (static_cast<int>(level) < static_cast<int>(m_level))
                {
                    return;
                }
            }

            // Build formatted log line: "[timestamp] [LEVEL] message"
            const TimePoint ts = now();
            const std::string tsStr = formatTimestamp(ts, "%Y-%m-%d %H:%M:%S");
            const char *levelStr = toString(level);

            std::string line;
            line.reserve(tsStr.size() + message.size() + 16);
            line.append("[");
            line.append(tsStr);
            line.append("] [");
            line.append(levelStr);
            line.append("] ");
            line.append(message);

            // Write to sinks (console and optional file) under one lock.
            writeLine(line);
        }

        const char *Logger::toString(LogLevel level) noexcept
        {
            switch (level)
            {
            case LogLevel::TRACE:    return "TRACE";
            case LogLevel::DEBUG:    return "DEBUG";
            case LogLevel::INFO:     return "INFO";
            case LogLevel::WARN:     return "WARN";
            case LogLevel::ERROR:    return "ERROR";
            case LogLevel::CRITICAL: return "CRITICAL";
            default:                 return "UNKNOWN";
            }
        }

        void Logger::writeLine(std::string_view line)
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            if (m_console)
            {
                (*m_console) << line << '\n';
                m_console->flush();
            }

            if (m_fileEnabled && m_file.is_open())
            {
                m_file << line << '\n';
                m_file.flush();
            }
        }

        // ------------ Global logger accessor ------------

        Logger &getLogger()
        {
            // Lazy-initialized, process-wide logger.
            // Default: stderr only, INFO level.
            static Logger instance;
            return instance;
        }

    } // namespace Utils
} // namespace LogTool
