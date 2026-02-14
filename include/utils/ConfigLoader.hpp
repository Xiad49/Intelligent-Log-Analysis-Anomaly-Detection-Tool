#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>
#include <mutex>

namespace LogTool
{
    namespace Utils
    {
        /**
         * ConfigLoader
         *
         * Responsibilities:
         *  - Load a simple text configuration file (key = value format).
         *  - Expose read-only access to configuration values.
         *  - Provide typed getters with defaults (for robustness).
         *
         * Format assumptions (for a basic, robust parser in ConfigLoader.cpp):
         *  - Each line is: key = value
         *  - Lines starting with '#' or ';' are comments.
         *  - Empty lines are ignored.
         *  - Whitespace around key and value is trimmed.
         *
         * Example:
         *   log_level        = INFO
         *   input_log_path   = /var/log/app.log
         *   window_size_secs = 60
         */
        class ConfigLoader
        {
        public:
            ConfigLoader() = default;

            // Non-copyable but movable, to avoid accidental implicit copies of config state.
            ConfigLoader(const ConfigLoader &)            = delete;
            ConfigLoader &operator=(const ConfigLoader &) = delete;

            ConfigLoader(ConfigLoader &&) noexcept        = default;
            ConfigLoader &operator=(ConfigLoader &&) noexcept = default;

            ~ConfigLoader() = default;

            /**
             * Load configuration from a file path.
             *
             * Returns true on success, false if the file cannot be opened.
             * Parsing errors on individual lines are ignored; valid lines are kept.
             */
            bool loadFromFile(const std::string &filePath);

            /**
             * Manually set a configuration key-value pair.
             * This can be useful for tests or overriding values from code.
             */
            void set(std::string key, std::string value);

            /// Check if a key exists in the loaded configuration.
            bool hasKey(std::string_view key) const;

            /// Get raw string value for a key; returns std::nullopt if missing.
            std::optional<std::string> getString(std::string_view key) const;

            /// Get string value or a default if the key is missing.
            std::string getStringOr(std::string_view key,
                                    std::string_view defaultValue) const;

            /// Get integer value; returns std::nullopt if missing or invalid.
            std::optional<int> getInt(std::string_view key) const;

            /// Get integer value or a default if missing/invalid.
            int getIntOr(std::string_view key, int defaultValue) const;

            /// Get double value; returns std::nullopt if missing or invalid.
            std::optional<double> getDouble(std::string_view key) const;

            /// Get double value or a default if missing/invalid.
            double getDoubleOr(std::string_view key, double defaultValue) const;

            /**
             * Get boolean value; returns std::nullopt if missing or invalid.
             *
             * Accepted true values (case-insensitive): "1", "true", "yes", "on"
             * Accepted false values (case-insensitive): "0", "false", "no", "off"
             */
            std::optional<bool> getBool(std::string_view key) const;

            /// Get boolean value or a default if missing/invalid.
            bool getBoolOr(std::string_view key, bool defaultValue) const;

            /// Access the underlying map (read-only) if needed by advanced components.
            const std::unordered_map<std::string, std::string> &all() const noexcept
            {
                return m_values;
            }

        private:
            // Helper used by typed getters to read a raw string under a lock.
            std::optional<std::string> getRawUnlocked(std::string_view key) const;

        private:
            // All configuration data is stored as string key -> string value.
            std::unordered_map<std::string, std::string> m_values;

            // Protects m_values for thread-safe reads/writes if config is updated at runtime.
            mutable std::mutex m_mutex;
        };

        /**
         * Global configuration accessor.
         *
         * Typical usage:
         *   auto &config = getGlobalConfig();
         *   if (!config.loadFromFile("config.ini")) {
         *       // handle missing config
         *   }
         *
         * Other modules can then read settings safely:
         *   int windowSize = config.getIntOr("window_size_secs", 60);
         */
        ConfigLoader &getGlobalConfig();

    } // namespace Utils
} // namespace LogTool
