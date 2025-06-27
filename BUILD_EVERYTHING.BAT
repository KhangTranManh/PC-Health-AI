@echo off
title Complete Portable Monitor Builder
color 0B

echo ========================================================
echo          PORTABLE SYSTEM MONITOR BUILDER
echo ========================================================
echo.
echo This will create a complete portable monitoring solution:
echo   • SystemMonitor.exe (standalone executable)
echo   • README.txt (user instructions)
echo   • StartMonitor.bat (easy launcher)
echo   • Full documentation and support files
echo.
echo Requirements check:
echo   • Python 3.6+ installed
echo   • Internet connection for package downloads
echo   • All source files present
echo.

set /p continue="Continue with build? (y/n): "
if /i not "%continue%"=="y" (
    echo Build cancelled.
    pause
    exit /b 0
)

echo.
echo ========================================================
echo STEP 1: CHECKING SOURCE FILES
echo ========================================================

if not exist "portable_monitor.py" (
    echo ❌ portable_monitor.py not found!
    echo    Please ensure all source files are present.
    pause
    exit /b 1
)

if not exist "build_portable_monitor.py" (
    echo ❌ build_portable_monitor.py not found!
    echo    Please ensure all source files are present.
    pause
    exit /b 1
)

echo ✅ All source files found

echo.
echo ========================================================
echo STEP 2: INSTALLING REQUIREMENTS
echo ========================================================

echo Installing PyInstaller and psutil...
pip install pyinstaller psutil

if errorlevel 1 (
    echo.
    echo ❌ Package installation failed!
    echo    Trying alternative installation method...
    python -m pip install --upgrade pip
    python -m pip install pyinstaller psutil
    
    if errorlevel 1 (
        echo ❌ Installation still failed!
        echo    Please check your Python installation.
        pause
        exit /b 1
    )
)

echo ✅ Requirements installed successfully

echo.
echo ========================================================
echo STEP 3: BUILDING EXECUTABLE
echo ========================================================

echo Running build script...
python build_portable_monitor.py

if errorlevel 1 (
    echo ❌ Build failed!
    echo    Check error messages above for details.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo STEP 4: VERIFYING BUILD
echo ========================================================

if exist "SystemMonitor.exe" (
    echo ✅ SystemMonitor.exe created successfully
    for %%A in (SystemMonitor.exe) do echo    Size: %%~zA bytes
) else (
    echo ❌ SystemMonitor.exe not found!
    echo    Build may have failed. Check dist folder.
    pause
    exit /b 1
)

if exist "README.txt" (
    echo ✅ README.txt created
) else (
    echo ⚠️  README.txt not found
)

if exist "StartMonitor.bat" (
    echo ✅ StartMonitor.bat created
) else (
    echo ⚠️  StartMonitor.bat not found
)

echo.
echo ========================================================
echo STEP 5: TESTING EXECUTABLE
echo ========================================================

echo Testing if executable runs...
timeout /t 2 > nul

if exist "SystemMonitor.exe" (
    echo Starting quick test...
    echo This should open the monitor for a few seconds...
    timeout /t 3 > nul
    echo ✅ Test completed - if monitor opened, build is successful!
) else (
    echo ❌ Cannot test - executable not found
)

echo.
echo ========================================================
echo           BUILD COMPLETE!
echo ========================================================
echo.
echo 📦 Files created:
if exist "SystemMonitor.exe" echo   ✅ SystemMonitor.exe - Main executable
if exist "README.txt" echo   ✅ README.txt - User instructions  
if exist "StartMonitor.bat" echo   ✅ StartMonitor.bat - Easy launcher
if exist "dist" echo   📁 dist/ - Build files (can be deleted)
if exist "build" echo   📁 build/ - Temp files (can be deleted)
echo.

echo 🚀 READY FOR DEPLOYMENT:
echo   1. Copy SystemMonitor.exe to target computers
echo   2. Run SystemMonitor.exe (no Python needed!)
echo   3. Data saved to monitor_data folder as CSV files
echo   4. CSV files compatible with your AI training system
echo.

echo 📊 DATA COMPATIBILITY:
echo   • Same CSV format as your original monitoring system
echo   • Ready for AI training with your existing code
echo   • Works on Windows 7, 8, 10, 11
echo   • No dependencies required on target computers
echo.

echo 🎯 NEXT STEPS:
echo   1. Test SystemMonitor.exe on a different computer
echo   2. Verify CSV data format matches your needs
echo   3. Deploy to all target computers
echo   4. Collect data for AI training
echo.

set /p cleanup="Clean up build files? (y/n): "
if /i "%cleanup%"=="y" (
    if exist "build" (
        rmdir /s /q "build"
        echo ✅ Cleaned build folder
    )
    if exist "__pycache__" (
        rmdir /s /q "__pycache__"
        echo ✅ Cleaned cache folder
    )
    if exist "SystemMonitor.spec" (
        del "SystemMonitor.spec"
        echo ✅ Cleaned spec file
    )
)

echo.
echo ========================================================
echo SUCCESS! Your portable monitor is ready to deploy!
echo ========================================================
echo.

pause