#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <ctime>

namespace Utils
{
    // Utility function to trim whitespace from the beginning and end of a string
    inline std::string ltrim(const std::string& str)
    {
        std::string result = str;
        result.erase(result.begin(), std::find_if(result.begin(), result.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
        return result;
    }

    inline std::string rtrim(const std::string& str)
    {
        std::string result = str;
        result.erase(std::find_if(result.rbegin(), result.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), result.end());
        return result;
    }

    inline std::string trim(const std::string& str)
    {
        return ltrim(rtrim(str));
    }

    // Utility function to convert a string to uppercase
    inline std::string toUpper(const std::string& str)
    {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::toupper);
        return result;
    }

    // Utility function to split a string by a delimiter
    inline std::vector<std::string_view> split(std::string_view str, char delimiter, bool skipEmpty = false)
    {
        std::vector<std::string_view> result;
        size_t start = 0, end = 0;

        while ((end = str.find(delimiter, start)) != std::string_view::npos)
        {
            if (end != start || !skipEmpty)
            {
                result.push_back(str.substr(start, end - start));
            }
            start = end + 1;
        }

        if (start < str.size() || !skipEmpty)
        {
            result.push_back(str.substr(start));
        }

        return result;
    }

    // Utility function to parse a timestamp in "YYYY-MM-DD HH:MM:SS" format
    inline std::optional<std::chrono::system_clock::time_point> parseTimestamp(const std::string_view str)
    {
        std::tm tm = {};
        if (str.size() != 19) // Ensure format is "YYYY-MM-DD HH:MM:SS"
            return std::nullopt;

        // Parse the timestamp assuming the format "YYYY-MM-DD HH:MM:SS"
        if (sscanf(str.data(), "%4d-%2d-%2d %2d:%2d:%2d",
                   &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
        {
            return std::nullopt;
        }

        // Adjust tm values to match std::tm expectations
        tm.tm_year -= 1900;  // Years since 1900
        tm.tm_mon -= 1;      // Months are 0-based
        tm.tm_isdst = -1;    // Daylight saving time not known

        std::time_t time = std::mktime(&tm);
        if (time == -1)
        {
            return std::nullopt;
        }

        return std::chrono::system_clock::from_time_t(time);
    }

    // Utility function to convert a time_point to a string (formatted as "YYYY-MM-DD HH:MM:SS")
    inline std::string formatTimestamp(std::chrono::system_clock::time_point timePoint)
    {
        std::time_t time = std::chrono::system_clock::to_time_t(timePoint);
        std::tm tm = *std::localtime(&time);
        char buffer[20];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
        return std::string(buffer);
    }

    // Utility function to check if a string contains a substring (case-insensitive)
    inline bool contains(std::string_view haystack, std::string_view needle)
    {
        return haystack.find(needle) != std::string_view::npos;
    }

} // namespace Utils

#endif // UTILS_HPP
