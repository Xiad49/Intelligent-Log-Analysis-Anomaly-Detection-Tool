
# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name
project(MyProject)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/include)

# Add the source files
file(GLOB SOURCES "src/*.cpp")

# Add the executable
add_executable(MyProject ${SOURCES})

# Optionally, link to any libraries (if needed)
# target_link_libraries(MyProject ${LIBRARIES})

# Set the output directory for the executable
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/output)
