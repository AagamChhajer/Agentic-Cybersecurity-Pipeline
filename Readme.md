# Project Setup Guide

This guide provides step-by-step instructions on how to set up this project on a new device using Poetry with the existing `pyproject.toml` and `poetry.lock` files.

## Prerequisites

1. **Python**: Ensure Python 3.x is installed on your system.
2. **Poetry**: If not already installed, follow the instructions below.

## 1. Install Poetry

For Windows:
Open PowerShell and run:

```powershell
winget install --id Python.Poetry
```

For MacOS / Linux:
Open a terminal and run:

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

## 4. Activate the Virtual Environment

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

## 5. Verify the Setup

Confirm the installation by checking Python version and installed packages:

```powershell
python --version
pip list
```

## 6. (Optional) Run the Project

Start the project or run scripts as needed. If the project has a main file, run it like so:

```powershell
python main.py
```

## Troubleshooting

* If you encounter any issues with Python versions, make sure the correct version is installed and set up using:

```powershell
poetry env use python3.x
```

## Contributing

Feel free to contribute by submitting a pull request or reporting issues.

## License

This project is licensed under the MIT License - see the LICENSE file for details.