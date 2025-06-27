@echo off
title System Monitor Setup
color 0A

echo ========================================
echo   Portable System Monitor Setup
echo ========================================
echo.
echo This script will:
echo 1. Install required Python packages
echo 2. Build the portable executable
echo 3. Create supporting files
echo.

pause

echo.
echo Step 1: Installing required packages...
echo ----------------------------------------
pip install pyinstaller psutil
echo.

if errorlevel 1 (
    echo ❌ Package installation failed!
    echo Please check your Python and pip installation
    pause
    exit /b 1
)

echo ✅ Packages installed successfully!
echo.

echo Step 2: Building portable executable...
echo ----------------------------------------
python build_portable_monitor.py
echo.

if errorlevel 1 (
    echo ❌ Build failed!
    echo Please check the error messages above
    pause
    exit /b 1
)

echo.
echo Step 3: Setup complete!
echo ----------------------------------------
echo.
echo Files created:
echo   ✅ SystemMonitor.exe (portable executable)
echo   ✅ README.txt (instructions)
echo   ✅ StartMonitor.bat (launcher)
echo.

echo ========================================
echo   Ready to Deploy!
echo ========================================
echo.
echo To use on computers without Python:
echo   1. Copy SystemMonitor.exe to target PC
echo   2. Run SystemMonitor.exe
echo   3. Data saved to monitor_data folder
echo.
echo The CSV files are compatible with your AI training system!
echo.

pause