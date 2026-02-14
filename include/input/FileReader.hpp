#pragma once

#include <string>
#include <string_view>
#include <fstream>
#include <optional>
#include <mutex>

namespace LogTool
{
    namespace Input
    {
        /**
         * FileReader
         *
         * Responsibilities:
         *  - Provide efficient, stream-based reading of large log files.
         *  - Expose a simple line-oriented API (nextLine) to the parser layer.
         *  - Manage file resources via RAII.
         *
         * Design notes:
         *  - Uses std::ifstream with an internal read buffer.
         *  - Designed primarily for single-threaded ownership; callers can
         *    create multiple FileReader instances for parallel parsing of
         *    different files or file segments.
         *  - Not copyable (owning a file handle), but movable.
         */
        class FileReader
        {
        public:
            /// Default-constructed FileReader is not associated with any file.
            FileReader() = default;

            /**
             * Construct and open a file immediately.
             * If open fails, isOpen() will return false.
             */
            explicit FileReader(const std::string &filePath);

            // Non-copyable: owning a file handle should not be implicitly copied.
            FileReader(const FileReader &)            = delete;
            FileReader &operator=(const FileReader &) = delete;

            // Movable: allows transferring ownership if needed.
            FileReader(FileReader &&other) noexcept;
            FileReader &operator=(FileReader &&other) noexcept;

            /// Destructor closes the file if it is open (RAII).
            ~FileReader();

            /**
             * Open a file for reading.
             * Returns true on success, false if opening fails.
             * Any previously open file is closed first.
             */
            bool open(const std::string &filePath);

            /// Close the underlying file stream explicitly (optional).
            void close() noexcept;

            /// Check whether the file is currently open and ready.
            bool isOpen() const noexcept;

            /// Get the path of the currently opened file (empty if none).
            std::string filePath() const;

            /**
             * Read the next line from the file.
             *
             * Returns:
             *   - std::optional<std::string> with the line content (without '\n')
             *   - std::nullopt when EOF is reached or an error occurs.
             *
             * This method is the main interface used by the log parser.
             */
            std::optional<std::string> nextLine();

            /**
             * Reset the read position to the beginning of the file.
             * Returns true on success, false if not open or if seek fails.
             */
            bool rewind();

        private:
            /// Helper to release any current file and reset state.
            void reset() noexcept;

        private:
            std::ifstream m_stream;       // RAII-managed file stream
            std::string   m_filePath;     // path to the currently open file
        };

    } // namespace Input
} // namespace LogTool
