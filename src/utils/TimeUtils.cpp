#include "utils/TimeUtils.hpp"

#include <iomanip>
#include <sstream>

namespace LogTool
{
    namespace Utils
    {
        // -------- Basic conversions (these may be inline in the header) --------

        TimePoint from_time_t(std::time_t t) noexcept
        {
            return Clock::from_time_t(t);
        }

        std::time_t to_time_t(TimePoint tp) noexcept
        {
            return Clock::to_time_t(tp);
        }

        TimePoint now() noexcept
        {
            return Clock::now();
        }

        // -------- Formatting helpers --------

        std::string formatTimestamp(TimePoint tp, std::string_view format)
        {
            std::time_t t = to_time_t(tp);
            std::tm tm_buf{};
        #if defined(_WIN32)
            localtime_s(&tm_buf, &t);
        #else
            localtime_r(&t, &tm_buf);
        #endif

            // Use std::ostringstream instead of exposing strftime directly
            // so we keep the implementation localized here.
            std::ostringstream oss;
            oss << std::put_time(&tm_buf, format.data());
            return oss.str();
        }

        std::string toIso8601(TimePoint tp)
        {
            // ISO-like format: 2025-10-03T14:23:45
            return formatTimestamp(tp, "%Y-%m-%dT%H:%M:%S");
        }

        // -------- Parsing helpers --------

        namespace
        {
            // Small internal helper to convert a numeric substring to int.
            // Throws std::invalid_argument on non-digits.
            int parseIntField(std::string_view sv)
            {
                int value = 0;
                for (char c : sv)
                {
                    if (c < '0' || c > '9')
                    {
                        throw std::invalid_argument("Non-digit in numeric field");
                    }
                    value = value * 10 + (c - '0');
                }
                return value;
            }
        } // anonymous namespace

        std::optional<TimePoint> parseTimestamp(std::string_view sv)
        {
            // Expected format: "YYYY-MM-DD HH:MM:SS" (length >= 19)
            if (sv.size() < 19)
            {
                return std::nullopt;
            }

            std::tm tm_buf{};
            tm_buf.tm_isdst = -1; // let the C library figure out DST

            try
            {
                const int year  = parseIntField(sv.substr(0, 4));
                const int month = parseIntField(sv.substr(5, 2));
                const int day   = parseIntField(sv.substr(8, 2));
                const int hour  = parseIntField(sv.substr(11, 2));
                const int min   = parseIntField(sv.substr(14, 2));
                const int sec   = parseIntField(sv.substr(17, 2));

                tm_buf.tm_year = year - 1900;
                tm_buf.tm_mon  = month - 1;
                tm_buf.tm_mday = day;
                tm_buf.tm_hour = hour;
                tm_buf.tm_min  = min;
                tm_buf.tm_sec  = sec;
            }
            catch (...)
            {
                // Any parse error results in failure.
                return std::nullopt;
            }

            std::time_t t = std::mktime(&tm_buf);
            if (t == static_cast<std::time_t>(-1))
            {
                return std::nullopt;
            }
            return from_time_t(t);
        }

        std::optional<TimePoint> parseUnixSeconds(std::string_view sv)
        {
            if (sv.empty())
            {
                return std::nullopt;
            }

            std::time_t value = 0;
            for (char c : sv)
            {
                if (c < '0' || c > '9')
                {
                    return std::nullopt;
                }
                value = static_cast<std::time_t>(value * 10 + (c - '0'));
            }

            return from_time_t(value);
        }

        // -------- Epoch conversions and differences --------

        std::int64_t toMillisSinceEpoch(TimePoint tp) noexcept
        {
            const auto ms = std::chrono::time_point_cast<milliseconds>(tp)
                            .time_since_epoch();
            return static_cast<std::int64_t>(ms.count());
        }

        TimePoint fromMillisSinceEpoch(std::int64_t ms) noexcept
        {
            return TimePoint(milliseconds(ms));
        }

        std::int64_t diffMillis(TimePoint start, TimePoint end) noexcept
        {
            return std::chrono::duration_cast<milliseconds>(end - start).count();
        }

        std::int64_t diffSeconds(TimePoint start, TimePoint end) noexcept
        {
            return std::chrono::duration_cast<seconds>(end - start).count();
        }

        // -------- Window helpers --------

        bool inWindow(TimePoint ts,
                      TimePoint windowStart,
                      TimePoint windowEnd) noexcept
        {
            return ts >= windowStart && ts < windowEnd;
        }

        // Note: advanceWindow is a template; its definition is typically
        // kept in the header to avoid linker issues. If you explicitly
        // instantiate it for specific durations, you can place those
        // instantiations here.

        // -------- ScopedTimer (RAII) --------

        ScopedTimer::ScopedTimer(TimePoint &target) noexcept
            : target_(target),
              start_(Clock::now()),
              moved_(false)
        {
        }

        ScopedTimer::ScopedTimer(ScopedTimer &&other) noexcept
            : target_(other.target_),
              start_(other.start_),
              moved_(false)
        {
            other.moved_ = true;
        }

        ScopedTimer::~ScopedTimer() noexcept
        {
            if (!moved_)
            {
                // Store the scope end time into the referenced TimePoint.
                target_ = Clock::now();
            }
        }

    } // namespace Utils
} // namespace LogTool
