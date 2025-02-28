# Project Setup Guide

This guide provides step-by-step instructions on how to set up this project on a new device using Poetry with the existing `pyproject.toml` and `poetry.lock` files.

## Prerequisites

1. **Python**: Ensure Python 3.x is installed on your system.
2. **Poetry**: If not already installed, follow the instructions below.

## 1. Install Poetry

For Windows: Open PowerShell and run:

```powershell
winget install --id Python.Poetry
```

For MacOS / Linux: Open a terminal and run:

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Verify Installation:

```powershell
poetry --version
```

## 2. Clone or Copy the Project

Copy the entire project folder containing `pyproject.toml` and `poetry.lock` to your new device or clone the repository:

```bash
git clone <repository-url>
cd <project-folder>
```

## 3. Install Dependencies

Navigate to the project directory and install dependencies using Poetry:

```powershell
poetry install
```

This will:
* Create a virtual environment.
* Install all dependencies exactly as specified in `poetry.lock`.

## 4. Install Required Security Tools

The project requires several security tools. Follow these instructions to install them:

### Nmap

**Windows:**
1. Download the installer from [nmap.org](https://nmap.org/download.html)
2. Run the installer and follow the prompts
3. Verify installation: `nmap --version`

**MacOS:**
```bash
brew install nmap
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install nmap
```

### Gobuster

**Windows:**
1. Download the latest release from [GitHub](https://github.com/OJ/gobuster/releases)
2. Extract the executable to a location in your PATH
3. Verify installation: `gobuster --version`

**MacOS:**
```bash
brew install gobuster
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install gobuster
```

### Ffuf

**All platforms:**
1. Download the latest release from [GitHub](https://github.com/ffuf/ffuf/releases)
2. Extract to a location in your PATH
3. Verify installation: `ffuf -V`

**MacOS (alternative):**
```bash
brew install ffuf
```

**Go installation (all platforms with Go):**
```bash
go install github.com/ffuf/ffuf@latest
```

### SQLMap

**All platforms:**
```bash
pip install sqlmap
```

**Linux (alternative):**
```bash
sudo apt update
sudo apt install sqlmap
```

## 5. Activate the Virtual Environment

After installation, activate the environment using:

```powershell
poetry shell
```

Alternatively, find the virtual environment path using:

```powershell
poetry env info
```

Then activate it manually:

```powershell
# For Windows (PowerShell)
& "path\to\virtualenv\Scripts\Activate.ps1"

# For MacOS / Linux
source path/to/virtualenv/bin/activate
```

## 6. Run the Application

After activating the environment, run the Streamlit application:

```bash
streamlit run app.py
```

This will start the web interface and open it in your default browser.

## Project Architecture and Workflow

### Overview

The Agentic Cybersecurity Pipeline is an automated security assessment tool that orchestrates multiple security scanning tools through an AI-driven workflow. The system uses LangGraph to create a state-driven workflow that intelligently generates, executes, and analyzes security tasks.

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Initialize     │     │  Execute        │     │  Analyze        │
│  Security Audit ├────►│  Security Task  ├────►│  Results        │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                         │
         ┌────────────────────────────────────┐          │
         │                                    │          ▼
         │                             ┌─────────────────┐
         │                             │  Continue or    │
         │                             │  Generate Report│
         │                             └─────────────────┘
         │                                    │
         │                                    ▼
         │                             ┌─────────────────┐
         └────────────────────────────►│  Generate       │
                                       │  Report         │
                                       └─────────────────┘
```

### Core Components

1. **State Management System**: Uses LangGraph's StateGraph to maintain and transition between states in the security assessment workflow.

2. **Security Scanners**: 
   - **NmapScanner**: Port and service discovery
   - **GobusterScanner**: Directory and file enumeration
   - **FfufScanner**: Web content discovery and fuzzing
   - **SqlmapScanner**: SQL injection testing

3. **AI-Driven Analysis**: Leverages OpenAI's models to:
   - Break down security objectives into executable tasks
   - Analyze scan results for vulnerabilities
   - Generate follow-up tasks based on findings
   - Create comprehensive security reports

4. **Target Scope Enforcement**: The `TargetScope` class ensures all scanning activities remain within allowed domains and IP ranges.

5. **Streamlit Web Interface**: Provides a user-friendly interface for configuring and monitoring security assessments.

### Workflow Explanation

1. **Initialization**: The system takes a security objective and scope, then uses AI to create an initial set of security tasks.

2. **Task Execution**: Security tasks are executed in priority order, with built-in retry mechanisms and timeout handling.

3. **Result Analysis**: After each task completes, results are analyzed to identify vulnerabilities and generate follow-up tasks.

4. **Adaptive Planning**: The system dynamically adjusts its task queue based on findings, prioritizing the most promising paths.

5. **Report Generation**: Once all tasks are complete or the maximum steps are reached, a comprehensive security report is generated.

### Security Features

- **Scope Enforcement**: All targets are validated against allowed domains and IP ranges
- **Logging System**: Comprehensive logging for audit trails and debugging
- **Error Handling**: Robust error handling with retry mechanisms
- **Task Deduplication**: Prevents redundant tasks from being executed

## Demo Video

Watch our demo video to see the pipeline in action:

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/60mABSoYDec/0.jpg)](https://github.com/user-attachments/assets/87785301-7c85-4b75-9264-12e3a9ec67ca)



## 7. Verify the Setup

Confirm the installation by checking Python version and installed packages:

```powershell
python --version
pip list
```

## Troubleshooting

* If you encounter any issues with Python versions, make sure the correct version is installed and set up using:

```powershell
poetry env use python3.x
```

* If security tools aren't working, ensure they're properly installed and added to your system PATH

## Contributing

Feel free to contribute by submitting a pull request or reporting issues.

## License

This project is licensed under the MIT License - see the LICENSE file for details.