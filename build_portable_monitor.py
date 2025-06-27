#!/usr/bin/env python3
"""
Build script to create standalone executable
Creates a portable system monitor that works without Python installed
File: build_portable_monitor.py

Requirements:
pip install pyinstaller psutil

Usage:
python build_portable_monitor.py
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_requirements():
    """Check if required packages are installed"""
    required = ['pyinstaller', 'psutil']
    missing = []
    
    for package in required:
        try:
            __import__(package)
            print(f"✅ {package} found")
        except ImportError:
            missing.append(package)
            print(f"❌ {package} missing")
    
    if missing:
        print(f"\n📦 Install missing packages:")
        print(f"pip install {' '.join(missing)}")
        return False
    
    return True

def build_executable():
    """Build the standalone executable"""
    print("\n🔨 Building standalone executable...")
    
    # Check if portable_monitor.py exists
    if not os.path.exists('portable_monitor.py'):
        print("❌ portable_monitor.py not found!")
        print("   Make sure you have the portable_monitor.py file in the same directory")
        return False
    
    try:
        # PyInstaller command
        cmd = [
            'pyinstaller',
            '--onefile',  # Single executable file
            '--console',  # Keep console window
            '--name', 'SystemMonitor',  # Executable name
            '--hidden-import', 'psutil',
            '--clean',  # Clean cache
            'portable_monitor.py'
        ]
        
        print(f"🚀 Running: {' '.join(cmd)}")
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Build successful!")
            
            # Check if executable was created
            exe_path = Path('dist/SystemMonitor.exe')
            if exe_path.exists():
                size_mb = exe_path.stat().st_size / (1024 * 1024)
                print(f"📦 Executable created: {exe_path} ({size_mb:.1f} MB)")
                return True
            else:
                print("❌ Executable not found in expected location")
                return False
        else:
            print("❌ Build failed!")
            if result.stdout:
                print("STDOUT:", result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ Build error: {e}")
        return False

def create_readme():
    """Create README file for the executable"""
    readme_content = """# Portable System Monitor

## What it does
- Collects system performance data (CPU, memory, disk, network)
- Monitors basic security status (antivirus, threats)
- Saves data to CSV files
- Works on any Windows computer without Python installed

## How to use
1. Run SystemMonitor.exe
2. Choose option 1 for single check or option 2 for continuous monitoring
3. Data is saved to 'monitor_data' folder as CSV files

## Data collected
- CPU usage percentage
- Memory usage and capacity
- Disk usage and capacity
- Network activity
- Security status (antivirus, real-time protection)
- System uptime
- Process count
- Battery level (if laptop)
- Temperature (if sensors available)

## Files created
- monitor_[ComputerName]_[OS].csv - Main data file
- Stored in 'monitor_data' folder next to executable

## CSV Format
The generated CSV files contain these columns:
timestamp, computer_name, computer_id, os_system, cpu_percent, 
memory_percent, memory_used_gb, memory_total_gb, disk_percent, 
disk_free_gb, disk_total_gb, process_count, temperature, 
uptime_hours, network_sent_mb, network_recv_mb, security_score, 
antivirus_enabled, real_time_protection, definition_age_days, 
suspicious_activity_count, vulnerability_count, security_software_count

## Requirements
- Windows 7 or later
- No Python installation needed
- Administrator rights recommended for full security data

## Troubleshooting
- If antivirus blocks: Add exception for SystemMonitor.exe
- If permissions error: Run as administrator
- Data files are created in the same folder as the executable
- If security data shows defaults: Run with administrator privileges

## Usage Examples

Single Check:
1. Run SystemMonitor.exe
2. Choose option 1
3. View system status and check monitor_data folder for CSV file

Continuous Monitoring:
1. Run SystemMonitor.exe
2. Choose option 2
3. Enter duration (e.g., 60 minutes)
4. Enter interval (e.g., 300 seconds = 5 minutes)
5. Let it run and collect data automatically

## Security Features
- Detects Windows Defender status
- Monitors for high resource usage (potential threats)
- Calculates security scores
- Identifies vulnerabilities (high disk usage, etc.)
"""
    
    with open('README.txt', 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print("✅ Created README.txt")

def create_batch_launcher():
    """Create batch file for easy launching"""
    batch_content = """@echo off
title Portable System Monitor
color 0A

echo ==========================================
echo    Portable System Monitor
echo ==========================================
echo.
echo Starting monitor...
echo.

SystemMonitor.exe

echo.
echo ==========================================
echo Monitor finished. 
echo Check monitor_data folder for CSV files.
echo ==========================================
echo.
pause
"""
    
    with open('StartMonitor.bat', 'w', encoding='utf-8') as f:
        f.write(batch_content)
    
    print("✅ Created StartMonitor.bat")

def create_quick_install_script():
    """Create script to install requirements"""
    install_content = """@echo off
title Install Requirements
color 0C

echo ==========================================
echo   Installing Requirements
echo ==========================================
echo.

echo Installing PyInstaller and psutil...
pip install pyinstaller psutil

echo.
echo ==========================================
echo Installation complete!
echo ==========================================
echo.
echo Now run: python build_portable_monitor.py
echo.
pause
"""
    
    with open('install_requirements.bat', 'w', encoding='utf-8') as f:
        f.write(install_content)
    
    print("✅ Created install_requirements.bat")

def cleanup_build_files():
    """Clean up build artifacts"""
    cleanup_items = ['build', '__pycache__', 'SystemMonitor.spec']
    
    for item in cleanup_items:
        if os.path.exists(item):
            try:
                if os.path.isdir(item):
                    shutil.rmtree(item)
                else:
                    os.remove(item)
                print(f"🧹 Cleaned: {item}")
            except Exception as e:
                print(f"⚠️  Could not clean {item}: {e}")

def copy_executable_to_root():
    """Copy executable to root directory for easy access"""
    exe_path = Path('dist/SystemMonitor.exe')
    if exe_path.exists():
        try:
            shutil.copy2(exe_path, 'SystemMonitor.exe')
            print("✅ Copied SystemMonitor.exe to current directory")
            return True
        except Exception as e:
            print(f"⚠️  Could not copy executable: {e}")
            return False
    return False

def main():
    """Main build process"""
    print("🚀 Portable System Monitor Builder")
    print("=" * 50)
    
    # Check if portable_monitor.py exists
    if not os.path.exists('portable_monitor.py'):
        print("❌ portable_monitor.py not found!")
        print("   Create the portable_monitor.py file first")
        return
    
    # Check requirements
    if not check_requirements():
        print("\n❌ Missing requirements.")
        print("   Run: install_requirements.bat")
        print("   Or manually: pip install pyinstaller psutil")
        create_quick_install_script()
        return
    
    # Build executable
    if not build_executable():
        print("❌ Failed to build executable")
        return
    
    # Copy executable to current directory
    copy_executable_to_root()
    
    # Create supporting files
    create_readme()
    create_batch_launcher()
    create_quick_install_script()
    
    # Cleanup
    cleanup_build_files()
    
    print("\n🎉 BUILD COMPLETE!")
    print("=" * 30)
    print("📦 Files created:")
    print("  • SystemMonitor.exe - Main executable")
    print("  • README.txt - Instructions")
    print("  • StartMonitor.bat - Easy launcher")
    print("  • install_requirements.bat - For future builds")
    
    if os.path.exists('dist'):
        print("  • dist/ - Build directory (can be deleted)")
    
    print("\n📋 To distribute:")
    print("  1. Copy SystemMonitor.exe to target computer")
    print("  2. Double-click to run (or use StartMonitor.bat)")
    print("  3. Data saved to 'monitor_data' folder")
    
    print("\n📊 CSV files generated are compatible with:")
    print("  • Your AI training system")
    print("  • Excel and data analysis tools")
    print("  • Any CSV processing software")
    
    print("\n✅ Ready for deployment!")

if __name__ == "__main__":
    main()