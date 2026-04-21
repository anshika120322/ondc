@echo off
REM =============================================================================
REM ONDC QA Framework - Windows Setup Script
REM =============================================================================
REM This script helps new users set up the test environment on Windows
REM =============================================================================

echo.
echo ========================================================================
echo   ONDC QA Framework - Windows Setup
echo ========================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.12 or higher from https://python.org
    pause
    exit /b 1
)

echo [1/5] Python version check...
python --version

REM Check if virtual environment exists
if not exist "venv\" (
    echo.
    echo [2/5] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created successfully
) else (
    echo.
    echo [2/5] Virtual environment already exists
)

REM Activate virtual environment
echo.
echo [3/5] Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)

REM Upgrade pip
echo.
echo [4/5] Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies
echo.
echo [5/5] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    echo.
    echo Try running these commands manually:
    echo   1. venv\Scripts\activate
    echo   2. pip uninstall bson -y
    echo   3. pip install -r requirements.txt
    pause
    exit /b 1
)

REM Verify setup
echo.
echo ========================================================================
echo   Verifying Installation...
echo ========================================================================
python scripts\verify_setup.py
if errorlevel 1 (
    echo.
    echo WARNING: Some checks failed. Please review the output above.
    echo See SETUP.md for troubleshooting help.
) else (
    echo.
    echo ========================================================================
    echo   SUCCESS! Environment is ready for testing
    echo ========================================================================
    echo.
    echo Next steps:
    echo   1. Configure your environment in resources\environments.yml
    echo   2. Run a test:
    echo      python driver.py --test-case ondc_gateway_search_functional --env qa
    echo.
)

pause
