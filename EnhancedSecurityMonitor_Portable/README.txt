
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
