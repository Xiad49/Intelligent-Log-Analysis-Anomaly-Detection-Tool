#include "input/FileReader.hpp"

#include <utility>   // std::move

namespace LogTool
{
    namespace Input
    {
        FileReader::FileReader(const std::string &filePath)
            : m_stream(),
              m_filePath()
        {
            open(filePath);
        }

        FileReader::FileReader(FileReader &&other) noexcept
            : m_stream(std::move(other.m_stream)),
              m_filePath(std::move(other.m_filePath))
        {
            // 'other' is left in a valid but unspecified state.
        }

        FileReader &FileReader::operator=(FileReader &&other) noexcept
        {
            if (this != &other)
            {
                // Close any currently open stream before taking over.
                if (m_stream.is_open())
                {
                    m_stream.close();
                }

                m_stream   = std::move(other.m_stream);
                m_filePath = std::move(other.m_filePath);
            }
            return *this;
        }

        FileReader::~FileReader()
        {
            // RAII: ensure file is closed on destruction.
            if (m_stream.is_open())
            {
                m_stream.close();
            }
        }

        bool FileReader::open(const std::string &filePath)
        {
            // Close any existing file first.
            if (m_stream.is_open())
            {
                m_stream.close();
            }

            m_filePath.clear();

            // Open in text mode for log files; rely on buffering of ifstream.
            m_stream.open(filePath, std::ios::in);
            if (!m_stream.is_open())
            {
                return false;
            }

            m_filePath = filePath;
            // Clear any previous error flags and position at beginning.
            m_stream.clear();
            m_stream.seekg(0, std::ios::beg);
            return true;
        }

        void FileReader::close() noexcept
        {
            if (m_stream.is_open())
            {
                m_stream.close();
            }
            m_filePath.clear();
        }

        bool FileReader::isOpen() const noexcept
        {
            return m_stream.is_open();
        }

        std::string FileReader::filePath() const
        {
            return m_filePath;
        }

        std::optional<std::string> FileReader::nextLine()
        {
            if (!m_stream.is_open())
            {
                return std::nullopt;
            }

            std::string line;
            if (!std::getline(m_stream, line))
            {
                // EOF or error.
                return std::nullopt;
            }

            // Drop trailing '\r' for Windows-style line endings.
            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }

            return line;
        }

        bool FileReader::rewind()
        {
            if (!m_stream.is_open())
            {
                return false;
            }

            m_stream.clear();                       // clear EOF and error flags
            m_stream.seekg(0, std::ios::beg);       // seek back to start
            return static_cast<bool>(m_stream);
        }

        void FileReader::reset() noexcept
        {
            if (m_stream.is_open())
            {
                m_stream.close();
            }
            m_filePath.clear();
        }

    } // namespace Input
} // namespace LogTool
