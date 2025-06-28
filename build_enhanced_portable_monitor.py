# build_enhanced_portable_monitor.py
"""
Enhanced Build script to create portable executable for Enhanced Security Monitor
Run this on a computer with Python to create the .exe file
"""

import os
import subprocess
import sys
import shutil
from pathlib import Path

def install_requirements():
    """Install required packages"""
    requirements = [
        "psutil>=5.9.0",
        "requests>=2.28.0", 
        "pyinstaller>=5.0.0"
    ]
    
    print("[PACKAGES] Installing required packages...")
    for package in requirements:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"[OK] Installed {package}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to install {package}: {e}")
            return False
    return True

def create_spec_file():
    """Create PyInstaller spec file for enhanced monitor"""
    spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['enhanced_portable_security_monitor.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'psutil',
        'requests',
        'email.mime.multipart',
        'email.mime.base',
        'email.mime.text',
        'smtplib',
        'json',
        'csv',
        'threading',
        'queue',
        'zipfile',
        'subprocess',
        'hashlib',
        'shutil',
        'pathlib'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'pandas',
        'PIL',
        'tkinter',
        'scipy',
        'IPython'
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='EnhancedSecurityMonitor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
'''
    
    with open('EnhancedSecurityMonitor.spec', 'w') as f:
        f.write(spec_content)
    print("[OK] Created Enhanced PyInstaller spec file")

def build_executable():
    """Build the enhanced portable executable"""
    print("[BUILD] Building enhanced portable executable...")
    
    try:
        # Build using spec file
        result = subprocess.run([
            sys.executable, "-m", "PyInstaller",
            "--clean",
            "EnhancedSecurityMonitor.spec"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[OK] Build completed successfully!")
            return True
        else:
            print(f"[ERROR] Build failed: {result.stderr}")
            print(f"Output: {result.stdout}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Build error: {e}")
        return False

def create_deployment_package():
    """Create deployment package with all necessary files"""
    print("[PACKAGE] Creating enhanced deployment package...")
    
    package_dir = "EnhancedSecurityMonitor_Portable"
    
    try:
        # Create package directory
        if os.path.exists(package_dir):
            shutil.rmtree(package_dir)
        os.makedirs(package_dir)
        
        # Copy executable
        exe_path = os.path.join("dist", "EnhancedSecurityMonitor.exe")
        if os.path.exists(exe_path):
            shutil.copy2(exe_path, package_dir)
            print("[OK] Copied enhanced executable")
        else:
            print("[ERROR] Enhanced executable not found!")
            return False
        
        # Create README
        readme_content = """
# Enhanced Portable Security Monitor

## Quick Start
1. Run EnhancedSecurityMonitor.exe
2. Follow the setup wizard on first run
3. Configure email settings for data sync
4. Start monitoring!

## Enhanced Features
- [+] Comprehensive security scanning (like colector.py)
- [+] Windows Defender status monitoring
- [+] Temperature monitoring
- [+] Threat and vulnerability detection
- [+] Security software detection
- [+] 23 columns of data (same as KxcPc)
- [+] Automatic data sync via email/webhook
- [+] Portable - no installation required
- [+] Works without Python installed

## Data Format
Creates files in format: system_security_[laptop_name]_combined.csv
- Contains all 23 columns like your KxcPc computer
- Compatible with existing analysis tools
- Comprehensive security monitoring data

## Setup Instructions
1. On first run, you'll be prompted to configure:
   - Email settings for data sync
   - Sync interval
   - Collection interval

2. For Gmail, use an "App Password":
   - Go to Google Account settings
   - Security > 2-Step Verification > App passwords
   - Generate password for "Mail"

## Files Created
- config/ - Configuration files
- data/ - Collected monitoring data (CSV format)
- logs/ - Application logs

## Monitoring Capabilities
- CPU, Memory, Disk usage
- Network activity
- Process monitoring
- Temperature sensors
- Security score calculation
- Windows Defender status
- Antivirus real-time protection
- Definition age tracking
- Suspicious activity detection
- Vulnerability scanning
- Security software detection

## Automatic Sync
When internet is available, the monitor will automatically:
- Create comprehensive data packages
- Send via email/webhook
- Clean up old files
- Include detailed security reports

## Support
Check the logs/ folder for troubleshooting information.
All features from the comprehensive colector.py are included!
"""
        
        with open(os.path.join(package_dir, "README.txt"), 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        # Create batch file for easy running
        batch_content = """@echo off
echo Starting Enhanced Portable Security Monitor...
echo This version includes comprehensive security monitoring!
EnhancedSecurityMonitor.exe
pause
"""
        
        with open(os.path.join(package_dir, "Run_Enhanced_Monitor.bat"), 'w', encoding='utf-8') as f:
            f.write(batch_content)
        
        print(f"[OK] Enhanced deployment package created in {package_dir}/")
        print(f"[SIZE] Package size: {get_dir_size(package_dir):.1f} MB")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Error creating enhanced package: {e}")
        return False

def get_dir_size(path):
    """Get directory size in MB"""
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.path.exists(fp):
                total += os.path.getsize(fp)
    return total / (1024 * 1024)

def main():
    """Main build process for enhanced monitor"""
    print("ENHANCED PORTABLE SECURITY MONITOR BUILDER")
    print("=" * 60)
    print("This will create a .exe with ALL features from colector.py!")
    print("[+] 23 columns of data")
    print("[+] Comprehensive security scanning")
    print("[+] Temperature monitoring")
    print("[+] Threat detection")
    print("[+] Email sync functionality")
    print("=" * 60)
    
    # Check if source file exists
    if not os.path.exists("enhanced_portable_security_monitor.py"):
        print("[ERROR] enhanced_portable_security_monitor.py not found!")
        print("   Make sure you have the enhanced version in the current directory")
        return
    
    # Install requirements
    if not install_requirements():
        print("[ERROR] Failed to install requirements")
        return
    
    # Create spec file
    create_spec_file()
    
    # Build executable
    if not build_executable():
        print("[ERROR] Build failed")
        return
    
    # Create deployment package
    if not create_deployment_package():
        print("[ERROR] Package creation failed")
        return
    
    print("\n[SUCCESS] ENHANCED BUILD COMPLETE!")
    print("Package: Your enhanced portable security monitor is ready!")
    print(f"Location: EnhancedSecurityMonitor_Portable/")
    print("\nTo deploy:")
    print("   1. Copy the EnhancedSecurityMonitor_Portable folder to any computer")
    print("   2. Run EnhancedSecurityMonitor.exe")
    print("   3. Complete the setup wizard")
    print("   4. Start comprehensive monitoring!")
    print("\nFeatures included:")
    print("   [+] Same 23 columns as your KxcPc computer")
    print("   [+] Comprehensive security scanning")
    print("   [+] Auto email sync")
    print("   [+] File format: system_security_[laptop_name]_combined.csv")
    print("   [+] No Python installation required on target computer")
    
    # Create ZIP for easy distribution
    try:
        shutil.make_archive("EnhancedSecurityMonitor_Portable", 'zip', "EnhancedSecurityMonitor_Portable")
        zip_size = os.path.getsize("EnhancedSecurityMonitor_Portable.zip") / (1024 * 1024)
        print(f"[ZIP] Created EnhancedSecurityMonitor_Portable.zip ({zip_size:.1f} MB)")
    except Exception as e:
        print(f"[WARNING] Could not create ZIP: {e}")

if __name__ == "__main__":
    main()