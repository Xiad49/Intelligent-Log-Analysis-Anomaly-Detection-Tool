// File: src/utils/StringUtils.cpp

#include "utils/StringUtils.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace {
    // File-local helper
    bool isSpace(unsigned char c) noexcept {
        return std::isspace(c) != 0;
    }
}

namespace LogTool::Utils {

std::string escapeJson(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
    {
        switch (c)
        {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

std::string escapeCsv(const std::string& s)
{
    bool needQuotes = false;
    for (char c : s)
    {
        if (c == ',' || c == '"' || c == '\n' || c == '\r')
        {
            needQuotes = true;
            break;
        }
    }

    std::string out;
    out.reserve(s.size() + 4);

    for (char c : s)
    {
        if (c == '"') out += "\"\"";
        else out += c;
    }

    return needQuotes ? "\"" + out + "\"" : out;
}

std::string trimLeft(const std::string& input)
{
    auto it = std::find_if(input.begin(), input.end(),
                           [](unsigned char ch) { return !isSpace(ch); });
    return std::string(it, input.end());
}

std::string trimRight(const std::string& input)
{
    auto it = std::find_if(input.rbegin(), input.rend(),
                           [](unsigned char ch) { return !isSpace(ch); });
    return std::string(input.begin(), it.base());
}

std::string trim(const std::string& input)
{
    return trimRight(trimLeft(input));
}

std::string toLower(std::string input)
{
    std::transform(input.begin(), input.end(), input.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return input;
}

std::string toUpper(std::string input)
{
    std::transform(input.begin(), input.end(), input.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return input;
}

bool startsWith(const std::string& str, const std::string& prefix, bool caseSensitive)
{
    if (prefix.size() > str.size()) return false;

    if (!caseSensitive)
        return toLower(str.substr(0, prefix.size())) == toLower(prefix);

    return std::equal(prefix.begin(), prefix.end(), str.begin());
}

bool endsWith(const std::string& str, const std::string& suffix, bool caseSensitive)
{
    if (suffix.size() > str.size()) return false;

    const std::size_t offset = str.size() - suffix.size();

    if (!caseSensitive)
        return toLower(str.substr(offset)) == toLower(suffix);

    return std::equal(suffix.begin(), suffix.end(), str.begin() + static_cast<std::ptrdiff_t>(offset));
}

std::vector<std::string> split(const std::string& input, char delimiter, bool skipEmpty)
{
    std::vector<std::string> tokens;

    std::string current;
    current.reserve(input.size());

    for (char ch : input)
    {
        if (ch == delimiter)
        {
            if (!current.empty() || !skipEmpty)
                tokens.push_back(current);
            current.clear();
        }
        else
        {
            current.push_back(ch);
        }
    }

    if (!current.empty() || !skipEmpty)
        tokens.push_back(current);

    return tokens;
}

std::vector<std::string> splitWhitespace(const std::string& input, bool /*skipEmpty*/)
{
    // Note: operator>> already skips whitespace and never produces empty tokens.
    std::vector<std::string> tokens;
    std::istringstream iss(input);
    for (std::string token; iss >> token; )
        tokens.push_back(token);
    return tokens;
}

std::string join(const std::vector<std::string>& parts, const std::string& delimiter)
{
    if (parts.empty()) return {};

    std::size_t totalSize = 0;
    for (const auto& s : parts) totalSize += s.size();
    totalSize += delimiter.size() * (parts.size() - 1);

    std::string result;
    result.reserve(totalSize);

    for (std::size_t i = 0; i < parts.size(); ++i)
    {
        if (i) result += delimiter;
        result += parts[i];
    }

    return result;
}

std::string replaceAll(std::string input, const std::string& from, const std::string& to)
{
    if (from.empty()) return input;

    std::size_t pos = 0;
    while ((pos = input.find(from, pos)) != std::string::npos)
    {
        input.replace(pos, from.length(), to);
        pos += to.length();
    }
    return input;
}

bool iequals(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return false;

    for (std::size_t i = 0; i < a.size(); ++i)
    {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

} // namespace LogTool::Utils
