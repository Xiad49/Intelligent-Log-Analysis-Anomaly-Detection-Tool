# Intelligent Log Analysis & Anomaly Detection Tool

A high-performance C++ based log analysis and anomaly detection system
designed to process large-scale log files efficiently.\
This project focuses on structured parsing, statistical analysis,
rule-based detection, and visualization-ready output generation.

------------------------------------------------------------------------

## 🚀 Project Overview

This system analyzes large log datasets (2MB--7MB+) and detects abnormal
behavior using:

-   Statistical anomaly detection
-   Rule-based detection
-   Spike detection
-   Burst pattern detection
-   IP frequency anomaly detection
-   Time-window based analysis
-   Z-score based statistical monitoring
-   Isolation Forest based anomaly scoring (visualized output)

The tool is designed for extensibility, modularity, and performance
using modern C++ and CMake.

------------------------------------------------------------------------

## 📂 Project Structure

    include/        → Header files (modular architecture)
    src/            → Source files (core implementation)
    data-set/       → Sample test log files
    output/         → Generated reports and visualizations
    .vscode/        → Debug and build configuration
    CMakeLists.txt  → CMake build configuration

------------------------------------------------------------------------

## 🧠 Core Modules

### 1️⃣ Input Processing

-   FileReader
-   LogParser

### 2️⃣ Core Engine

-   LogEntry
-   Anomaly
-   Core Engine
-   Report abstraction

### 3️⃣ Analysis Modules

-   FrequencyAnalyzer
-   PatternAnalyzer
-   TimeWindowAnalyzer

### 4️⃣ Anomaly Detection Modules

-   StatisticalDetector
-   SpikeDetector
-   BurstPatternDetector
-   IpFrequencyDetector
-   RuleBasedDetector

### 5️⃣ Reporting System

-   ConsoleReporter
-   CsvReporter
-   JsonReporter
-   ReportGenerator

### 6️⃣ Utilities

-   Logger
-   ConfigLoader
-   TimeUtils
-   StringUtils

------------------------------------------------------------------------

## 📊 Output & Visualization

The system generates:

-   CSV summaries
-   Time-series data
-   Log-level distributions
-   Error trends
-   Z-score trends
-   Service correlation matrices
-   Heatmaps
-   Isolation Forest anomaly scores
-   Auto-generated graph dashboards (PNG + HTML)

Generated graphs are saved inside:

    output/graphs_TIMESTAMP/

------------------------------------------------------------------------

## 🛠 Build Instructions

### 🔧 Requirements

-   C++17 compatible compiler
-   CMake 3.15+

### 🔨 Build Steps

``` bash
mkdir build
cd build
cmake ..
make
```

Executable will be generated after successful compilation.

------------------------------------------------------------------------

## ▶️ Running the Tool

Example usage:

``` bash
.\logtool.exe --graphs -o output "LOCATION\FILE_NAME"
```

Output files will be stored inside the `output/` directory.

------------------------------------------------------------------------

## 🧪 Included Test Datasets

-   sample_big_log_6MB.log
-   security_attack_log_4MB.log
-   corrupted_malformed_log_4MB.log
-   mixed_format_log_2\_3MB.log

These datasets allow benchmarking across: - Normal traffic - Security
attack simulations - Corrupted logs - Mixed-format logs

------------------------------------------------------------------------

## 📈 Key Features

-   Modular C++ architecture
-   Large log file support
-   Memory-efficient parsing
-   Time-based aggregation
-   Statistical anomaly detection
-   ML-integrated anomaly visualization
-   CSV & JSON export
-   Automated graph generation
-   Easily extendable detector framework

------------------------------------------------------------------------

## 🔮 Future Improvements

-   Real-time streaming support
-   Distributed processing
-   Deep learning based anomaly detection
-   Web dashboard integration
-   REST API support

------------------------------------------------------------------------

## 📄 License

This project is developed for research and educational purposes.

------------------------------------------------------------------------

## 👨‍💻 Author

SORWAR MD ZIAD BIN
