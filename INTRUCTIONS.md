# Portable System Monitor - Complete Guide

## 📁 File Structure
Create these 4 files in a new folder:

```
monitor_project/
├── portable_monitor.py          # Main monitor code
├── build_portable_monitor.py    # Build script
├── setup.bat                   # Quick setup
├── requirements.txt            # Dependencies
└── INSTRUCTIONS.md             # This file
```

## 🚀 Quick Start (Easiest Method)

1. **Save all files** in a new folder
2. **Run setup.bat** - this does everything automatically
3. **Get SystemMonitor.exe** - ready to deploy!

## 🔧 Manual Setup (Alternative)

If you prefer manual control:

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
# OR
pip install pyinstaller psutil
```

### Step 2: Build Executable
```bash
python build_portable_monitor.py
```

### Step 3: Deploy
Copy `SystemMonitor.exe` to target computers

## 📊 What You Get

### Generated Files:
- `SystemMonitor.exe` - Standalone executable (~15MB)
- `README.txt` - User instructions
- `StartMonitor.bat` - Easy launcher
- `monitor_data/` - Folder with CSV files

### CSV Data Format:
Compatible with your AI training system:
```
timestamp, computer_name, computer_id, os_system, cpu_percent, 
memory_percent, memory_used_gb, memory_total_gb, disk_percent, 
disk_free_gb, disk_total_gb, process_count, temperature, 
uptime_hours, network_sent_mb, network_recv_mb, security_score, 
antivirus_enabled, real_time_protection, definition_age_days, 
suspicious_activity_count, vulnerability_count, security_software_count
```

## 🎯 Usage on Target Computers

### For End Users:
1. Copy `SystemMonitor.exe` to any Windows PC
2. Double-click to run
3. Choose monitoring option:
   - **Option 1**: Single system check
   - **Option 2**: Continuous monitoring
4. Data automatically saved to CSV files

### Example Monitoring Session:
```
🚀 Portable System Monitor
==================================================
🎯 Running as standalone executable
🖥️  Portable Monitor - MyComputer_Windows
📁 Data: C:\Users\User\Desktop\monitor_data

📋 Options:
1. 📊 Single system check
2. 🔄 Continuous monitoring
3. 📁 Show data files
4. 🚪 Exit

Enter choice (1-4): 2
Duration in minutes (default 10): 60
Interval in seconds (default 60): 300

🔄 Continuous monitoring for 60 minutes
📊 Sampling every 300 seconds
Press Ctrl+C to stop early

📝 Sample 1: 
⏰ 2025-06-28T10:15:30
🖥️  CPU: 45.2% | Memory: 67.8% | Disk: 85.3%
🔒 Security: 85/100 | AV: ✅
   ✅ Saved
```

## 🔍 Data Collection Details

### System Metrics:
- **CPU**: Usage percentage and frequency
- **Memory**: Usage, capacity, swap status
- **Disk**: Usage, free space, total capacity
- **Network**: Data sent/received in MB
- **Processes**: Total running process count
- **Temperature**: System temperature (if available)
- **Battery**: Level and charging status (laptops)
- **Uptime**: Hours since last boot

### Security Monitoring:
- **Antivirus Status**: Enabled/disabled
- **Real-time Protection**: Active/inactive
- **Security Score**: 0-100 calculated score
- **Threat Detection**: High resource usage alerts
- **Vulnerabilities**: System issues (low disk space, etc.)
- **Security Software**: Count of security tools

## 🛠️ Troubleshooting

### Build Issues:
```bash
# If build fails, try:
pip install --upgrade pyinstaller psutil
python build_portable_monitor.py
```

### Runtime Issues:
- **Antivirus blocks**: Add exception for SystemMonitor.exe
- **Permission errors**: Run as administrator
- **Missing data**: Ensure monitor_data folder is writable

### For Maximum Data Accuracy:
- Run as administrator on target computers
- Ensure Windows PowerShell is available
- Keep executable in a writable directory

## 🎯 Integration with AI Training

The generated CSV files are designed to work with your AI training system:

1. **Collect data** from multiple computers using SystemMonitor.exe
2. **Combine CSV files** from different systems
3. **Train AI** using the combined dataset
4. **Deploy AI** for automated health analysis

### Combining Data:
```python
# Example: Combine multiple CSV files
import pandas as pd
import glob

csv_files = glob.glob("monitor_data/*.csv")
combined_df = pd.concat([pd.read_csv(f) for f in csv_files])
combined_df.to_csv("all_computers_data.csv", index=False)
```

## 📋 Deployment Checklist

### Before Distribution:
- [ ] Test SystemMonitor.exe on clean Windows PC
- [ ] Verify CSV files are generated correctly
- [ ] Confirm data format matches your AI system
- [ ] Check that security data is collected properly
- [ ] Test both single check and continuous monitoring
- [ ] Verify executable works without Python installed

### For Each Target Computer:
- [ ] Copy SystemMonitor.exe to desktop or Documents
- [ ] Run initial test to confirm it works
- [ ] Set up scheduled monitoring if needed
- [ ] Document computer name and location
- [ ] Ensure users know how to use it

## 🔄 Scheduled Monitoring Setup

### Windows Task Scheduler (Optional):
Create automated monitoring sessions:

1. Open Task Scheduler
2. Create Basic Task
3. Set trigger (daily, weekly, etc.)
4. Action: Start a program
5. Program: `C:\path\to\SystemMonitor.exe`
6. Add arguments: (none needed - will use menu)

### Batch Script for Automation:
Create `auto_monitor.bat`:
```batch
@echo off
cd /d "%~dp0"
echo 1 | SystemMonitor.exe
timeout /t 3600
echo 2 | SystemMonitor.exe
```

## 🔧 Advanced Configuration

### Custom Data Collection:
Modify `portable_monitor.py` before building to:
- Change default monitoring intervals
- Add custom security checks
- Modify CSV column names
- Add additional system metrics

### Build Customization:
Edit `build_portable_monitor.py` to:
- Change executable name
- Add custom icons
- Include additional files
- Modify build settings

## 📈 Data Analysis Examples

### Load Data in Python:
```python
import pandas as pd

# Load single computer data
df = pd.read_csv('monitor_data/monitor_Computer1_Windows.csv')

# Basic analysis
print(f"Data points: {len(df)}")
print(f"Date range: {df['timestamp'].min()} to {df['timestamp'].max()}")
print(f"Average CPU: {df['cpu_percent'].mean():.1f}%")
print(f"Average Security Score: {df['security_score'].mean():.1f}/100")
```

### Excel Analysis:
1. Open CSV file in Excel
2. Create charts from timestamp and metrics
3. Use conditional formatting for security scores
4. Create pivot tables for summary statistics

## 🚨 Security Considerations

### Antivirus Detection:
- Some antivirus software may flag the executable
- This is normal for PyInstaller-built executables
- Add exceptions if needed
- Consider code signing for enterprise deployment

### Data Privacy:
- CSV files contain system information
- No personal files or data are collected
- Network data is aggregate statistics only
- Consider data retention policies

### Administrator Rights:
- Full security data requires admin privileges
- Basic monitoring works with user rights
- PowerShell security checks need admin access
- Document privilege requirements for users

## 📞 Support and Maintenance

### Common User Questions:
**Q: "The program won't start"**
A: Check Windows version (7+), try running as administrator

**Q: "No security data is shown"**
A: Run as administrator for full Windows Defender access

**Q: "CSV file is empty"**
A: Check monitor_data folder permissions, try different location

**Q: "High CPU usage during monitoring"**
A: Normal during data collection, reduce monitoring frequency

### Updates and Maintenance:
- Rebuild executable for new features
- Test on different Windows versions
- Update security checks as needed
- Monitor for new psutil versions

## 📜 License and Distribution

### Usage Rights:
- Free to use and modify
- No licensing restrictions for internal use
- Credit appreciated but not required
- Enterprise deployment is permitted

### Distribution:
- Include README.txt with executable
- Provide basic usage instructions
- Consider creating installer for large deployments
- Test thoroughly before wide distribution

## 🎯 Success Metrics

### Deployment Success:
- [ ] Executable runs on target computers
- [ ] CSV files are generated consistently
- [ ] Data quality meets AI training requirements
- [ ] Users can operate the tool independently
- [ ] Security data is captured accurately

### Data Quality Indicators:
- Consistent timestamp formatting
- Complete system metrics in each record
- Security scores within expected ranges
- No missing or corrupted CSV files
- Data from multiple computer types

---

## 🎉 You're Ready!

With all these files, you have a complete portable monitoring solution that:

✅ **Works without Python** on any Windows computer
✅ **Collects the same data** as your original system
✅ **Generates AI-compatible CSV files**
✅ **Provides user-friendly interface**
✅ **Includes comprehensive documentation**

Just save all the code files, run `setup.bat`, and start deploying `SystemMonitor.exe` to your target computers!