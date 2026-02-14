#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <algorithm>
#include <cctype>
#include <sstream>

namespace LogTool::Utils {
    std::string escapeJson(const std::string& s);
    std::string escapeCsv(const std::string& s);
}

namespace LogTool
{
    namespace Utils
    {
        /**
         * String utility helpers for parsing and normalizing log text.
         *
         * All functions are:
         *  - Header-only, inline where appropriate for performance.
         *  - Stateless and thread-safe.
         *  - Using std::string_view where possible to avoid unnecessary copies.
         */

        /// Trim whitespace (space, tab, CR, LF) from the left side of the string view.
        inline std::string_view ltrim(std::string_view sv) noexcept
        {
            const auto it = std::find_if_not(
                sv.begin(),
                sv.end(),
                [](unsigned char ch) { return std::isspace(ch) != 0; }
            );
            return std::string_view(it, static_cast<std::size_t>(sv.end() - it));
        }

        /// Trim whitespace (space, tab, CR, LF) from the right side of the string view.
        inline std::string_view rtrim(std::string_view sv) noexcept
        {
            const auto it = std::find_if_not(
                sv.rbegin(),
                sv.rend(),
                [](unsigned char ch) { return std::isspace(ch) != 0; }
            );
            if (it == sv.rend())
            {
                return std::string_view{};
            }
            return std::string_view(sv.begin(),
                                    static_cast<std::size_t>(sv.rend() - it));
        }

        /// Trim whitespace from both ends of the string view.
        inline std::string_view trim(std::string_view sv) noexcept
        {
            return rtrim(ltrim(sv));
        }

        /// Convert a string to lowercase (returns a new std::string).
        inline std::string toLower(std::string_view sv)
        {
            std::string result;
            result.reserve(sv.size());
            std::transform(
                sv.begin(),
                sv.end(),
                std::back_inserter(result),
                [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); }
            );
            return result;
        }

        /// Convert a string to uppercase (returns a new std::string).
        inline std::string toUpper(std::string_view sv)
        {
            std::string result;
            result.reserve(sv.size());
            std::transform(
                sv.begin(),
                sv.end(),
                std::back_inserter(result),
                [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); }
            );
            return result;
        }

        /// Check if a string_view starts with a given prefix (case-sensitive).
        inline bool startsWith(std::string_view sv, std::string_view prefix) noexcept
        {
            return sv.size() >= prefix.size()
                   && sv.compare(0, prefix.size(), prefix) == 0;
        }

        /// Check if a string_view ends with a given suffix (case-sensitive).
        inline bool endsWith(std::string_view sv, std::string_view suffix) noexcept
        {
            return sv.size() >= suffix.size()
                   && sv.compare(sv.size() - suffix.size(), suffix.size(), suffix) == 0;
        }

        /// Case-insensitive equality comparison without allocations.
        inline bool iequals(std::string_view a, std::string_view b) noexcept
        {
            if (a.size() != b.size())
            {
                return false;
            }
            for (std::size_t i = 0; i < a.size(); ++i)
            {
                unsigned char ca = static_cast<unsigned char>(a[i]);
                unsigned char cb = static_cast<unsigned char>(b[i]);
                if (std::tolower(ca) != std::tolower(cb))
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * Split a string_view by a single-character delimiter.
         *
         * - Empty fields are preserved if keepEmpty == true.
         * - Whitespace around tokens is not trimmed automatically.
         *   Call trim() on each token if desired.
         */
        inline std::vector<std::string_view> split(
            std::string_view sv,
            char delimiter,
            bool keepEmpty = false)
        {
            std::vector<std::string_view> result;
            std::size_t start = 0;

            while (start <= sv.size())
            {
                const std::size_t pos = sv.find(delimiter, start);
                const bool found = (pos != std::string_view::npos);
                const std::size_t end = found ? pos : sv.size();

                if (end > start || keepEmpty)
                {
                    result.emplace_back(sv.data() + start, end - start);
                }

                if (!found)
                {
                    break;
                }
                start = end + 1;
            }

            return result;
        }

        /**
         * Split a string_view by a single-character delimiter,
         * trimming whitespace around each token.
         */
        inline std::vector<std::string_view> splitAndTrim(
            std::string_view sv,
            char delimiter,
            bool keepEmpty = false)
        {
            std::vector<std::string_view> raw = split(sv, delimiter, keepEmpty);
            std::vector<std::string_view> result;
            result.reserve(raw.size());

            for (auto part : raw)
            {
                std::string_view t = trim(part);
                if (!t.empty() || keepEmpty)
                {
                    result.push_back(t);
                }
            }
            return result;
        }

        /**
         * Safely parse an integer from a string_view.
         *
         * Returns std::nullopt if parsing fails or if there are
         * non-numeric trailing characters after trimming.
         */
        template <typename IntType>
        std::optional<IntType> parseInteger(std::string_view sv)
        {
            static_assert(std::is_integral<IntType>::value,
                          "parseInteger requires an integral type");

            sv = trim(sv);
            if (sv.empty())
            {
                return std::nullopt;
            }

            std::string s(sv); // local copy for stream parsing
            std::istringstream iss(s);
            IntType value{};
            iss >> value;

            if (!iss || !iss.eof())
            {
                return std::nullopt;
            }
            return value;
        }

        /**
         * Safely parse a floating-point number from a string_view.
         *
         * Returns std::nullopt if parsing fails or trailing characters exist.
         */
        template <typename FloatType>
        std::optional<FloatType> parseFloat(std::string_view sv)
        {
            static_assert(std::is_floating_point<FloatType>::value,
                          "parseFloat requires a floating-point type");

            sv = trim(sv);
            if (sv.empty())
            {
                return std::nullopt;
            }

            std::string s(sv);
            std::istringstream iss(s);
            FloatType value{};
            iss >> value;

            if (!iss || !iss.eof())
            {
                return std::nullopt;
            }
            return value;
        }

        /**
         * Replace all occurrences of 'from' with 'to' in a string.
         * This is useful for normalizing log messages.
         */
        inline void replaceAllInPlace(std::string &str,
                                      std::string_view from,
                                      std::string_view to)
        {
            if (from.empty())
            {
                return;
            }

            std::size_t pos = 0;
            while ((pos = str.find(from, pos)) != std::string::npos)
            {
                str.replace(pos, from.size(), to);
                pos += to.size();
            }
        }

        /// Return a copy of the input with all occurrences of 'from' replaced by 'to'.
        inline std::string replaceAll(std::string_view sv,
                                      std::string_view from,
                                      std::string_view to)
        {
            std::string result(sv);
            replaceAllInPlace(result, from, to);
            return result;
        }

        /// Check if a string_view contains a given substring (case-sensitive).
        inline bool contains(std::string_view sv, std::string_view needle) noexcept
        {
            if (needle.empty())
            {
                return true;
            }
            return sv.find(needle) != std::string_view::npos;
        }

    } // namespace Utils
} // namespace LogTool
