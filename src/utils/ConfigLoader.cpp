#include "utils/ConfigLoader.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace LogTool
{
    namespace Utils
    {
        namespace
        {
            // Trim whitespace from left and right of a std::string (in-place).
            inline void trimInPlace(std::string &s)
            {
                auto notSpace = [](unsigned char ch) {
                    return std::isspace(ch) == 0;
                };

                // Left trim
                auto it = std::find_if(s.begin(), s.end(), notSpace);
                s.erase(s.begin(), it);

                // Right trim
                auto rit = std::find_if(s.rbegin(), s.rend(), notSpace);
                s.erase(rit.base(), s.end());
            }

            // Case-insensitive comparison for small strings.
            inline bool iequals(std::string_view a, std::string_view b)
            {
                if (a.size() != b.size())
                    return false;
                for (std::size_t i = 0; i < a.size(); ++i)
                {
                    unsigned char ca = static_cast<unsigned char>(a[i]);
                    unsigned char cb = static_cast<unsigned char>(b[i]);
                    if (std::tolower(ca) != std::tolower(cb))
                        return false;
                }
                return true;
            }
        } // anonymous namespace

        bool ConfigLoader::loadFromFile(const std::string &filePath)
        {
            std::ifstream in(filePath);
            if (!in.is_open())
            {
                // Could not open file; keep existing config as-is.
                return false;
            }

            std::unordered_map<std::string, std::string> newValues;

            std::string line;
            while (std::getline(in, line))
            {
                // Remove any carriage return if present (Windows-style line endings).
                if (!line.empty() && line.back() == '\r')
                {
                    line.pop_back();
                }

                // Skip empty lines.
                if (line.empty())
                {
                    continue;
                }

                // Skip comments starting with '#' or ';' (after leading whitespace).
                std::string tmp = line;
                trimInPlace(tmp);
                if (tmp.empty())
                {
                    continue;
                }
                if (tmp[0] == '#' || tmp[0] == ';')
                {
                    continue;
                }

                // Split into key and value at the first '='.
                const auto pos = line.find('=');
                if (pos == std::string::npos)
                {
                    // Malformed line; ignore for robustness.
                    continue;
                }

                std::string key   = line.substr(0, pos);
                std::string value = line.substr(pos + 1);

                trimInPlace(key);
                trimInPlace(value);

                if (key.empty())
                {
                    continue;
                }

                // Last occurrence wins if key is repeated.
                newValues[std::move(key)] = std::move(value);
            }

            // Commit the new values under the mutex to avoid partial updates.
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_values = std::move(newValues);
            }

            return true;
        }

        void ConfigLoader::set(std::string key, std::string value)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_values[std::move(key)] = std::move(value);
        }

        bool ConfigLoader::hasKey(std::string_view key) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_values.find(std::string(key)) != m_values.end();
        }

        std::optional<std::string> ConfigLoader::getRawUnlocked(std::string_view key) const
        {
            auto it = m_values.find(std::string(key));
            if (it == m_values.end())
            {
                return std::nullopt;
            }
            return it->second;
        }

        std::optional<std::string> ConfigLoader::getString(std::string_view key) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return getRawUnlocked(key);
        }

        std::string ConfigLoader::getStringOr(std::string_view key,
                                              std::string_view defaultValue) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto v = getRawUnlocked(key);
            if (!v)
            {
                return std::string(defaultValue);
            }
            return *v;
        }

        std::optional<int> ConfigLoader::getInt(std::string_view key) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto v = getRawUnlocked(key);
            if (!v)
            {
                return std::nullopt;
            }

            try
            {
                std::size_t idx = 0;
                int value       = std::stoi(*v, &idx);
                if (idx != v->size())
                {
                    // Trailing characters make this invalid.
                    return std::nullopt;
                }
                return value;
            }
            catch (...)
            {
                return std::nullopt;
            }
        }

        int ConfigLoader::getIntOr(std::string_view key, int defaultValue) const
        {
            auto v = getInt(key);
            return v ? *v : defaultValue;
        }

        std::optional<double> ConfigLoader::getDouble(std::string_view key) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto v = getRawUnlocked(key);
            if (!v)
            {
                return std::nullopt;
            }

            try
            {
                std::size_t idx = 0;
                double value    = std::stod(*v, &idx);
                if (idx != v->size())
                {
                    return std::nullopt;
                }
                return value;
            }
            catch (...)
            {
                return std::nullopt;
            }
        }

        double ConfigLoader::getDoubleOr(std::string_view key,
                                         double defaultValue) const
        {
            auto v = getDouble(key);
            return v ? *v : defaultValue;
        }

        std::optional<bool> ConfigLoader::getBool(std::string_view key) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto v = getRawUnlocked(key);
            if (!v)
            {
                return std::nullopt;
            }

            std::string s = *v;
            trimInPlace(s);

            if (s.empty())
            {
                return std::nullopt;
            }

            if (iequals(s, "1") || iequals(s, "true") ||
                iequals(s, "yes") || iequals(s, "on"))
            {
                return true;
            }
            if (iequals(s, "0") || iequals(s, "false") ||
                iequals(s, "no") || iequals(s, "off"))
            {
                return false;
            }

            return std::nullopt;
        }

        bool ConfigLoader::getBoolOr(std::string_view key, bool defaultValue) const
        {
            auto v = getBool(key);
            return v ? *v : defaultValue;
        }

        ConfigLoader &getGlobalConfig()
        {
            // Process-wide, lazily created configuration.
            static ConfigLoader instance;
            return instance;
        }

    } // namespace Utils
} // namespace LogTool
