import psutil
import platform
import datetime
import time
import json
import csv
import os
import socket
import subprocess
import hashlib
import winreg
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.gridspec import GridSpec
import pandas as pd
import numpy as np
from typing import List, Dict, Any

class SecurityEnhancedSystemMonitor:
    """System monitor with built-in security scanning capabilities and data visualization"""
    
    def __init__(self):
        print("🛡️ Security-Enhanced System Monitor Starting...")
        
        # Get computer identification
        self.computer_name = self.get_computer_identifier()
        print(f"🏷️  Computer ID: {self.computer_name}")
        
        # Set up data directory (relative to script location)
        self.data_dir = "data"
        self.charts_dir = "charts"
        self.ensure_data_directory()
        
        self.data_log = []
        
        # Security scan cache
        self.last_security_scan = None
        self.security_scan_interval = 300  # 5 minutes between full scans
    
    def get_computer_identifier(self):
        """Get a unique identifier for this computer"""
        try:
            hostname = socket.gethostname()
            clean_name = hostname.replace(" ", "_").replace("-", "_")
            return clean_name
        except Exception as e:
            print(f"⚠️  Error getting computer name: {e}")
            return f"Unknown_Computer_{datetime.datetime.now().strftime('%Y%m%d')}"
    
    def ensure_data_directory(self):
        """Create data and charts directories if they don't exist"""
        try:
            for directory in [self.data_dir, self.charts_dir]:
                if not os.path.exists(directory):
                    os.makedirs(directory)
                    print(f"✅ Created directory: {directory}")
                else:
                    print(f"✅ Using existing directory: {directory}")
        except Exception as e:
            print(f"❌ Error creating directories: {e}")
            self.data_dir = "."
            self.charts_dir = "."
    
    def check_windows_defender_status(self):
        """Check Windows Defender status and last scan info"""
        security_info = {
            "antivirus_enabled": False,
            "real_time_protection": False,
            "last_scan_date": None,
            "last_scan_type": None,
            "threat_count": 0,
            "definition_age_days": None,
            "security_center_status": "unknown"
        }
        
        if platform.system() != "Windows":
            security_info["security_center_status"] = "non_windows"
            return security_info
        
        try:
            # Check Windows Defender status using PowerShell
            powershell_cmd = """
            Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, 
            QuickScanAge, FullScanAge, AntivirusSignatureAge | ConvertTo-Json
            """
            
            result = subprocess.run(
                ["powershell", "-Command", powershell_cmd],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                import json
                defender_status = json.loads(result.stdout)
                
                security_info["antivirus_enabled"] = defender_status.get("AntivirusEnabled", False)
                security_info["real_time_protection"] = defender_status.get("RealTimeProtectionEnabled", False)
                
                # Calculate last scan info
                quick_scan_age = defender_status.get("QuickScanAge")
                full_scan_age = defender_status.get("FullScanAge")
                
                if quick_scan_age is not None and full_scan_age is not None:
                    if quick_scan_age <= full_scan_age:
                        security_info["last_scan_type"] = "Quick"
                        security_info["last_scan_date"] = (datetime.datetime.now() - datetime.timedelta(days=quick_scan_age)).isoformat()
                    else:
                        security_info["last_scan_type"] = "Full"
                        security_info["last_scan_date"] = (datetime.datetime.now() - datetime.timedelta(days=full_scan_age)).isoformat()
                
                # Definition age
                sig_age = defender_status.get("AntivirusSignatureAge")
                if sig_age is not None:
                    security_info["definition_age_days"] = sig_age
                
                security_info["security_center_status"] = "active"
                
        except Exception as e:
            print(f"⚠️  Could not check Windows Defender status: {e}")
            security_info["security_center_status"] = "error"
        
        return security_info
    
    def check_running_security_software(self):
        """Detect running antivirus and security software"""
        security_processes = []
        known_security_processes = {
            # Antivirus
            "MsMpEng.exe": "Windows Defender",
            "avp.exe": "Kaspersky",
            "avast.exe": "Avast",
            "avgnt.exe": "Avira",
            "mbamservice.exe": "Malwarebytes",
            "mcshield.exe": "McAfee",
            "nod32krn.exe": "ESET NOD32",
            "bdagent.exe": "Bitdefender",
            "fsav32.exe": "F-Secure",
            "wrsa.exe": "Webroot",
            
            # Firewalls
            "zlclient.exe": "ZoneAlarm",
            "outpost.exe": "Outpost Firewall",
            
            # System monitors
            "procmon.exe": "Process Monitor",
            "wireshark.exe": "Wireshark",
            "fiddler.exe": "Fiddler"
        }
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name']
                    if proc_name in known_security_processes:
                        security_processes.append({
                            "process_name": proc_name,
                            "software_name": known_security_processes[proc_name],
                            "pid": proc.info['pid']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"⚠️  Error checking security processes: {e}")
        
        return security_processes
    
    def check_suspicious_processes(self):
        """Check for processes that might indicate security issues"""
        suspicious_indicators = []
        
        try:
            # High CPU usage processes (potential cryptominers)
            high_cpu_processes = []
            cpu_threshold = 80.0
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    if proc.info['cpu_percent'] > cpu_threshold:
                        high_cpu_processes.append({
                            "name": proc.info['name'],
                            "pid": proc.info['pid'],
                            "cpu_percent": proc.info['cpu_percent']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if high_cpu_processes:
                suspicious_indicators.append({
                    "type": "high_cpu_usage",
                    "severity": "medium",
                    "processes": high_cpu_processes
                })
            
            # Check for unusual network activity
            network_stats = psutil.net_io_counters()
            if hasattr(self, 'previous_network_stats'):
                bytes_sent_rate = (network_stats.bytes_sent - self.previous_network_stats.bytes_sent) / 60  # per second
                bytes_recv_rate = (network_stats.bytes_recv - self.previous_network_stats.bytes_recv) / 60
                
                # Flag high network activity (>10MB/s)
                if bytes_sent_rate > 10 * 1024 * 1024 or bytes_recv_rate > 10 * 1024 * 1024:
                    suspicious_indicators.append({
                        "type": "high_network_activity",
                        "severity": "low",
                        "sent_rate_mb": bytes_sent_rate / (1024 * 1024),
                        "recv_rate_mb": bytes_recv_rate / (1024 * 1024)
                    })
            
            self.previous_network_stats = network_stats
            
            # Check for processes with suspicious names
            suspicious_names = [
                "bitcoin", "miner", "crypto", "hack", "keylog", "trojan",
                "backdoor", "rootkit", "spyware", "adware"
            ]
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name'].lower()
                    for suspicious in suspicious_names:
                        if suspicious in proc_name:
                            suspicious_indicators.append({
                                "type": "suspicious_process_name",
                                "severity": "high",
                                "process": proc.info['name'],
                                "pid": proc.info['pid']
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"⚠️  Error checking suspicious processes: {e}")
        
        return suspicious_indicators
    
    def check_system_vulnerabilities(self):
        """Check for common system vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Check if Windows updates are pending
            if platform.system() == "Windows":
                try:
                    # Check Windows Update status
                    powershell_cmd = """
                    $Session = New-Object -ComObject Microsoft.Update.Session
                    $Searcher = $Session.CreateUpdateSearcher()
                    $SearchResult = $Searcher.Search("IsInstalled=0")
                    $SearchResult.Updates.Count
                    """
                    
                    result = subprocess.run(
                        ["powershell", "-Command", powershell_cmd],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0 and result.stdout.strip().isdigit():
                        pending_updates = int(result.stdout.strip())
                        if pending_updates > 0:
                            vulnerabilities.append({
                                "type": "pending_windows_updates",
                                "severity": "medium" if pending_updates < 10 else "high",
                                "count": pending_updates
                            })
                
                except Exception as e:
                    print(f"⚠️  Could not check Windows updates: {e}")
            
            # Check for open ports (potential security risk)
            open_ports = []
            for conn in psutil.net_connections():
                if conn.status == psutil.CONN_LISTEN and conn.laddr.ip == "0.0.0.0":
                    open_ports.append(conn.laddr.port)
            
            if len(open_ports) > 10:  # Many open ports could be suspicious
                vulnerabilities.append({
                    "type": "many_open_ports",
                    "severity": "low",
                    "port_count": len(open_ports),
                    "sample_ports": sorted(open_ports)[:10]
                })
            
            # Check system uptime (patch level indicator)
            boot_time = psutil.boot_time()
            uptime_days = (time.time() - boot_time) / (24 * 3600)
            
            if uptime_days > 30:  # System hasn't been rebooted in a month
                vulnerabilities.append({
                    "type": "long_uptime",
                    "severity": "low",
                    "uptime_days": round(uptime_days, 1)
                })
                
        except Exception as e:
            print(f"⚠️  Error checking vulnerabilities: {e}")
        
        return vulnerabilities
    
    def perform_security_scan(self, force=False):
        """Perform comprehensive security scan"""
        current_time = time.time()
        
        # Check if we need to run a new scan
        if not force and self.last_security_scan:
            if current_time - self.last_security_scan < self.security_scan_interval:
                return None  # Use cached results
        
        print("🔍 Performing security scan...")
        
        security_data = {
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "scan_duration_seconds": 0,
            "antivirus_status": self.check_windows_defender_status(),
            "security_software": self.check_running_security_software(),
            "suspicious_activity": self.check_suspicious_processes(),
            "vulnerabilities": self.check_system_vulnerabilities(),
            "security_score": 0
        }
        
        # Calculate security score (0-100)
        score = 100
        
        # Antivirus deductions
        if not security_data["antivirus_status"]["antivirus_enabled"]:
            score -= 30
        if not security_data["antivirus_status"]["real_time_protection"]:
            score -= 20
        
        # Definition age deductions
        def_age = security_data["antivirus_status"]["definition_age_days"]
        if def_age and def_age > 7:
            score -= min(20, def_age * 2)  # Up to 20 points for old definitions
        
        # Suspicious activity deductions
        for activity in security_data["suspicious_activity"]:
            if activity["severity"] == "high":
                score -= 25
            elif activity["severity"] == "medium":
                score -= 15
            elif activity["severity"] == "low":
                score -= 5
        
        # Vulnerability deductions
        for vuln in security_data["vulnerabilities"]:
            if vuln["severity"] == "high":
                score -= 20
            elif vuln["severity"] == "medium":
                score -= 10
            elif vuln["severity"] == "low":
                score -= 5
        
        security_data["security_score"] = max(0, score)
        
        # Calculate scan duration
        security_data["scan_duration_seconds"] = round(time.time() - current_time, 2)
        
        self.last_security_scan = current_time
        
        return security_data
    
    def get_current_status(self):
        """Get current system status with security information"""
        timestamp = datetime.datetime.now()
        
        # Get basic system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_freq = psutil.cpu_freq()
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        network_io = psutil.net_io_counters()
        process_count = len(psutil.pids())
        
        # Temperature and battery
        temperature = None
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                temp_sensor = list(temps.values())[0]
                if temp_sensor:
                    temperature = temp_sensor[0].current
        except:
            temperature = None
        
        battery_info = None
        try:
            battery = psutil.sensors_battery()
            if battery:
                battery_info = {
                    "percent": battery.percent,
                    "plugged": battery.power_plugged,
                    "time_left": battery.secsleft if battery.secsleft != psutil.POWER_TIME_UNLIMITED else None
                }
        except:
            battery_info = None
        
        # Perform security scan
        security_data = self.perform_security_scan()
        
        # Compile all data
        system_data = {
            "timestamp": timestamp.isoformat(),
            "computer_info": {
                "computer_name": socket.gethostname(),
                "computer_id": self.computer_name,
                "os_system": platform.system(),
                "os_release": platform.release(),
                "architecture": platform.architecture()[0]
            },
            "cpu": {
                "usage_percent": cpu_percent,
                "frequency_mhz": cpu_freq.current if cpu_freq else None,
                "cores_physical": psutil.cpu_count(logical=False),
                "cores_logical": psutil.cpu_count(logical=True)
            },
            "memory": {
                "total_gb": memory.total / (1024**3),
                "available_gb": memory.available / (1024**3),
                "used_gb": memory.used / (1024**3),
                "usage_percent": memory.percent,
                "swap_total_gb": swap.total / (1024**3),
                "swap_used_gb": swap.used / (1024**3),
                "swap_percent": swap.percent
            },
            "disk": {
                "total_gb": disk.total / (1024**3),
                "used_gb": disk.used / (1024**3),
                "free_gb": disk.free / (1024**3),
                "usage_percent": (disk.used / disk.total) * 100,
                "read_bytes": disk_io.read_bytes if disk_io else None,
                "write_bytes": disk_io.write_bytes if disk_io else None
            },
            "network": {
                "bytes_sent": network_io.bytes_sent,
                "bytes_received": network_io.bytes_recv,
                "packets_sent": network_io.packets_sent,
                "packets_received": network_io.packets_recv
            },
            "system": {
                "process_count": process_count,
                "temperature_celsius": temperature,
                "battery": battery_info,
                "uptime_hours": (time.time() - psutil.boot_time()) / 3600
            },
            "security": security_data if security_data else {"cached": True}
        }
        
        return system_data
    
    def display_current_status(self, data):
        """Display current status with security information"""
        print(f"\n🕐 STATUS AT: {data['timestamp']} - {data['computer_info']['computer_id']}")
        print("=" * 80)
        
        # System metrics
        print(f"🖥️  CPU Usage: {data['cpu']['usage_percent']:.1f}%")
        print(f"🧠 Memory: {data['memory']['used_gb']:.1f}GB / {data['memory']['total_gb']:.1f}GB ({data['memory']['usage_percent']:.1f}%)")
        print(f"💾 Disk: {data['disk']['used_gb']:.1f}GB / {data['disk']['total_gb']:.1f}GB ({data['disk']['usage_percent']:.1f}%)")
        print(f"🌐 Network: ↑{data['network']['bytes_sent']/(1024**2):.1f}MB sent, ↓{data['network']['bytes_received']/(1024**2):.1f}MB received")
        
        # Security information
        if "security" in data and not data["security"].get("cached"):
            security = data["security"]
            score = security["security_score"]
            
            # Security score with emoji
            if score >= 90:
                score_emoji = "🟢"
                score_status = "EXCELLENT"
            elif score >= 75:
                score_emoji = "🟡"
                score_status = "GOOD"
            elif score >= 60:
                score_emoji = "🟠"
                score_status = "FAIR"
            else:
                score_emoji = "🔴"
                score_status = "POOR"
            
            print(f"🛡️  Security Score: {score_emoji} {score}/100 ({score_status})")
            
            # Antivirus status
            av_status = security["antivirus_status"]
            av_emoji = "🟢" if av_status["antivirus_enabled"] else "🔴"
            print(f"🦠 Antivirus: {av_emoji} {'Enabled' if av_status['antivirus_enabled'] else 'Disabled'}")
            
            # Real-time protection
            rt_emoji = "🟢" if av_status["real_time_protection"] else "🔴"
            print(f"🛡️  Real-time Protection: {rt_emoji} {'Active' if av_status['real_time_protection'] else 'Inactive'}")
            
            # Last scan
            if av_status["last_scan_date"]:
                scan_date = datetime.datetime.fromisoformat(av_status["last_scan_date"])
                days_ago = (datetime.datetime.now() - scan_date).days
                scan_emoji = "🟢" if days_ago <= 7 else "🟡" if days_ago <= 30 else "🔴"
                print(f"🔍 Last Scan: {scan_emoji} {av_status['last_scan_type']} scan {days_ago} days ago")
            
            # Threats and issues
            if security["suspicious_activity"]:
                print(f"⚠️  Suspicious Activity: {len(security['suspicious_activity'])} items detected")
            
            if security["vulnerabilities"]:
                print(f"🚨 Vulnerabilities: {len(security['vulnerabilities'])} issues found")
        
        print("=" * 80)
    
    def load_data_from_files(self, computer_name=None):
        """Load historical data from CSV files for visualization"""
        if computer_name is None:
            computer_name = self.computer_name
        
        # Try to find CSV files for this computer
        csv_files = []
        for file in os.listdir(self.data_dir):
            if file.endswith('.csv') and computer_name in file:
                csv_files.append(os.path.join(self.data_dir, file))
        
        if not csv_files:
            print(f"❌ No CSV files found for computer: {computer_name}")
            return None
        
        # Load and combine data from all CSV files
        all_data = []
        for csv_file in csv_files:
            try:
                df = pd.read_csv(csv_file)
                all_data.append(df)
                print(f"📊 Loaded {len(df)} records from {os.path.basename(csv_file)}")
            except Exception as e:
                print(f"⚠️  Error loading {csv_file}: {e}")
        
        if not all_data:
            return None
        
        # Combine all data
        combined_df = pd.concat(all_data, ignore_index=True)
        
        # Convert timestamp to datetime
        try:
            combined_df['timestamp'] = pd.to_datetime(combined_df['timestamp'])
        except Exception as e:
            print(f"⚠️  Error parsing timestamps: {e}")
            return None
        
        # Sort by timestamp
        combined_df = combined_df.sort_values('timestamp')
        
        print(f"✅ Loaded total of {len(combined_df)} records for visualization")
        return combined_df
    
    def create_comprehensive_charts(self, computer_name=None, save_individual=True):
        """Create comprehensive charts showing system changes over time"""
        try:
            import matplotlib.pyplot as plt
            import matplotlib.dates as mdates
            from matplotlib.gridspec import GridSpec
        except ImportError:
            print("❌ Matplotlib not installed. Please install it with: pip install matplotlib pandas")
            return
        
        if computer_name is None:
            computer_name = self.computer_name
        
        # Load data
        df = self.load_data_from_files(computer_name)
        if df is None or len(df) < 2:
            print("❌ Insufficient data for visualization. Need at least 2 data points.")
            return
        
        print(f"📈 Creating comprehensive charts for {computer_name}...")
        
        # Set up the plot style
        plt.style.use('default')
        
        # Create timestamp for filenames
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 1. Create Dashboard Overview (all metrics in one chart)
        fig = plt.figure(figsize=(20, 12))
        fig.suptitle(f'System Performance Dashboard - {computer_name}', fontsize=16, fontweight='bold')
        
        gs = GridSpec(3, 3, figure=fig, hspace=0.3, wspace=0.3)
        
        # CPU Usage
        ax1 = fig.add_subplot(gs[0, 0])
        if 'cpu_percent' in df.columns:
            ax1.plot(df['timestamp'], df['cpu_percent'], color='#ff6b6b', linewidth=2, label='CPU Usage')
            ax1.fill_between(df['timestamp'], df['cpu_percent'], alpha=0.3, color='#ff6b6b')
            ax1.set_title('CPU Usage (%)', fontweight='bold')
            ax1.set_ylabel('Percentage')
            ax1.grid(True, alpha=0.3)
            ax1.set_ylim(0, 100)
        
        # Memory Usage
        ax2 = fig.add_subplot(gs[0, 1])
        if 'memory_percent' in df.columns:
            ax2.plot(df['timestamp'], df['memory_percent'], color='#4ecdc4', linewidth=2, label='Memory Usage')
            ax2.fill_between(df['timestamp'], df['memory_percent'], alpha=0.3, color='#4ecdc4')
            ax2.set_title('Memory Usage (%)', fontweight='bold')
            ax2.set_ylabel('Percentage')
            ax2.grid(True, alpha=0.3)
            ax2.set_ylim(0, 100)
        
        # Disk Usage
        ax3 = fig.add_subplot(gs[0, 2])
        if 'disk_percent' in df.columns:
            ax3.plot(df['timestamp'], df['disk_percent'], color='#45b7d1', linewidth=2, label='Disk Usage')
            ax3.fill_between(df['timestamp'], df['disk_percent'], alpha=0.3, color='#45b7d1')
            ax3.set_title('Disk Usage (%)', fontweight='bold')
            ax3.set_ylabel('Percentage')
            ax3.grid(True, alpha=0.3)
            ax3.set_ylim(0, 100)
        
        # Security Score
        ax4 = fig.add_subplot(gs[1, 0])
        if 'security_score' in df.columns:
            ax4.plot(df['timestamp'], df['security_score'], color='#96ceb4', linewidth=2, marker='o', markersize=4)
            ax4.fill_between(df['timestamp'], df['security_score'], alpha=0.3, color='#96ceb4')
            ax4.set_title('Security Score', fontweight='bold')
            ax4.set_ylabel('Score (0-100)')
            ax4.grid(True, alpha=0.3)
            ax4.set_ylim(0, 100)
        
        # Process Count
        ax5 = fig.add_subplot(gs[1, 1])
        if 'process_count' in df.columns:
            ax5.plot(df['timestamp'], df['process_count'], color='#feca57', linewidth=2)
            ax5.fill_between(df['timestamp'], df['process_count'], alpha=0.3, color='#feca57')
            ax5.set_title('Process Count', fontweight='bold')
            ax5.set_ylabel('Number of Processes')
            ax5.grid(True, alpha=0.3)
        
        # Network Activity
        ax6 = fig.add_subplot(gs[1, 2])
        if 'network_sent_mb' in df.columns and 'network_recv_mb' in df.columns:
            ax6.plot(df['timestamp'], df['network_sent_mb'], color='#ff9ff3', linewidth=2, label='Sent (MB)')
            ax6.plot(df['timestamp'], df['network_recv_mb'], color='#54a0ff', linewidth=2, label='Received (MB)')
            ax6.set_title('Network Activity', fontweight='bold')
            ax6.set_ylabel('MB')
            ax6.legend()
            ax6.grid(True, alpha=0.3)
        
        # Temperature (if available)
        ax7 = fig.add_subplot(gs[2, 0])
        if 'temperature' in df.columns and not df['temperature'].isna().all():
            valid_temp = df.dropna(subset=['temperature'])
            if len(valid_temp) > 0:
                ax7.plot(valid_temp['timestamp'], valid_temp['temperature'], color='#ff6348', linewidth=2)
                ax7.fill_between(valid_temp['timestamp'], valid_temp['temperature'], alpha=0.3, color='#ff6348')
                ax7.set_title('Temperature (°C)', fontweight='bold')
                ax7.set_ylabel('Celsius')
                ax7.grid(True, alpha=0.3)
            else:
                ax7.text(0.5, 0.5, 'No Temperature Data', ha='center', va='center', transform=ax7.transAxes)
                ax7.set_title('Temperature (°C)', fontweight='bold')
        else:
            ax7.text(0.5, 0.5, 'No Temperature Data', ha='center', va='center', transform=ax7.transAxes)
            ax7.set_title('Temperature (°C)', fontweight='bold')
        
        # Uptime
        ax8 = fig.add_subplot(gs[2, 1])
        if 'uptime_hours' in df.columns:
            uptime_days = df['uptime_hours'] / 24
            ax8.plot(df['timestamp'], uptime_days, color='#a55eea', linewidth=2)
            ax8.fill_between(df['timestamp'], uptime_days, alpha=0.3, color='#a55eea')
            ax8.set_title('System Uptime (Days)', fontweight='bold')
            ax8.set_ylabel('Days')
            ax8.grid(True, alpha=0.3)
        
        # Security Issues Count
        ax9 = fig.add_subplot(gs[2, 2])
        if 'suspicious_activity_count' in df.columns and 'vulnerability_count' in df.columns:
            ax9.plot(df['timestamp'], df['suspicious_activity_count'], color='#ff4757', linewidth=2, marker='o', markersize=4, label='Suspicious Activity')
            ax9.plot(df['timestamp'], df['vulnerability_count'], color='#ff6348', linewidth=2, marker='s', markersize=4, label='Vulnerabilities')
            ax9.set_title('Security Issues Count', fontweight='bold')
            ax9.set_ylabel('Count')
            ax9.legend()
            ax9.grid(True, alpha=0.3)
        
        # Format x-axis for all subplots
        for ax in [ax1, ax2, ax3, ax4, ax5, ax6, ax7, ax8, ax9]:
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
            ax.xaxis.set_major_locator(mdates.HourLocator(interval=max(1, len(df)//10)))
            plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        # Save dashboard
        dashboard_file = os.path.join(self.charts_dir, f"dashboard_{computer_name}_{timestamp}.png")
        plt.tight_layout()
        plt.savefig(dashboard_file, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"📊 Dashboard saved: {dashboard_file}")
        
        # 2. Create individual detailed charts if requested
        if save_individual:
            self._create_individual_charts(df, computer_name, timestamp)
        
        # 3. Create Security-focused chart
        self._create_security_chart(df, computer_name, timestamp)
        
        print(f"✅ All charts created successfully for {computer_name}")
        print(f"📁 Charts saved in: {self.charts_dir}")
    
    def _create_individual_charts(self, df, computer_name, timestamp):
        """Create individual detailed charts for each metric"""
        
        # CPU Usage detailed chart
        if 'cpu_percent' in df.columns:
            plt.figure(figsize=(12, 6))
            plt.plot(df['timestamp'], df['cpu_percent'], color='#ff6b6b', linewidth=2, marker='o', markersize=3)
            plt.fill_between(df['timestamp'], df['cpu_percent'], alpha=0.3, color='#ff6b6b')
            plt.title(f'CPU Usage Over Time - {computer_name}', fontsize=14, fontweight='bold')
            plt.xlabel('Time')
            plt.ylabel('CPU Usage (%)')
            plt.grid(True, alpha=0.3)
            plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
            plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=max(1, len(df)//10)))
            plt.xticks(rotation=45)
            plt.ylim(0, 100)
            plt.tight_layout()
            cpu_file = os.path.join(self.charts_dir, f"cpu_usage_{computer_name}_{timestamp}.png")
            plt.savefig(cpu_file, dpi=300, bbox_inches='tight')
            plt.close()
            print(f"📈 CPU chart saved: {cpu_file}")
        
        # Memory Usage detailed chart
        if 'memory_percent' in df.columns and 'memory_used_gb' in df.columns and 'memory_total_gb' in df.columns:
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
            
            # Memory percentage
            ax1.plot(df['timestamp'], df['memory_percent'], color='#4ecdc4', linewidth=2, marker='o', markersize=3)
            ax1.fill_between(df['timestamp'], df['memory_percent'], alpha=0.3, color='#4ecdc4')
            ax1.set_title(f'Memory Usage - {computer_name}', fontsize=14, fontweight='bold')
            ax1.set_ylabel('Memory Usage (%)')
            ax1.grid(True, alpha=0.3)
            ax1.set_ylim(0, 100)
            
            # Memory GB
            ax2.plot(df['timestamp'], df['memory_used_gb'], color='#4ecdc4', linewidth=2, marker='o', markersize=3, label='Used')
            ax2.plot(df['timestamp'], df['memory_total_gb'], color='#95a5a6', linewidth=2, linestyle='--', label='Total')
            ax2.fill_between(df['timestamp'], df['memory_used_gb'], alpha=0.3, color='#4ecdc4')
            ax2.set_xlabel('Time')
            ax2.set_ylabel('Memory (GB)')
            ax2.legend()
            ax2.grid(True, alpha=0.3)
            
            # Format x-axis
            for ax in [ax1, ax2]:
                ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
                ax.xaxis.set_major_locator(mdates.HourLocator(interval=max(1, len(df)//10)))
                plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
            
            plt.tight_layout()
            memory_file = os.path.join(self.charts_dir, f"memory_usage_{computer_name}_{timestamp}.png")
            plt.savefig(memory_file, dpi=300, bbox_inches='tight')
            plt.close()
            print(f"🧠 Memory chart saved: {memory_file}")
    
    def _create_security_chart(self, df, computer_name, timestamp):
        """Create a detailed security-focused chart"""
        security_columns = ['security_score', 'antivirus_enabled', 'real_time_protection', 
                           'suspicious_activity_count', 'vulnerability_count']
        
        # Check if we have security data
        has_security_data = any(col in df.columns for col in security_columns)
        
        if not has_security_data:
            print("⚠️  No security data found for security chart")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle(f'Security Analysis - {computer_name}', fontsize=16, fontweight='bold')
        
        # Security Score
        if 'security_score' in df.columns:
            axes[0,0].plot(df['timestamp'], df['security_score'], color='#27ae60', linewidth=3, marker='o', markersize=4)
            axes[0,0].fill_between(df['timestamp'], df['security_score'], alpha=0.3, color='#27ae60')
            axes[0,0].set_title('Security Score Over Time', fontweight='bold')
            axes[0,0].set_ylabel('Score (0-100)')
            axes[0,0].grid(True, alpha=0.3)
            axes[0,0].set_ylim(0, 100)
            
            # Add colored zones
            axes[0,0].axhspan(0, 60, alpha=0.1, color='red', label='Poor')
            axes[0,0].axhspan(60, 75, alpha=0.1, color='orange', label='Fair')
            axes[0,0].axhspan(75, 90, alpha=0.1, color='yellow', label='Good')
            axes[0,0].axhspan(90, 100, alpha=0.1, color='green', label='Excellent')
        
        # Protection Status
        if 'antivirus_enabled' in df.columns and 'real_time_protection' in df.columns:
            # Convert boolean to numeric for plotting
            av_numeric = df['antivirus_enabled'].astype(int)
            rt_numeric = df['real_time_protection'].astype(int)
            
            axes[0,1].plot(df['timestamp'], av_numeric, color='#3498db', linewidth=2, marker='o', markersize=4, label='Antivirus')
            axes[0,1].plot(df['timestamp'], rt_numeric, color='#e74c3c', linewidth=2, marker='s', markersize=4, label='Real-time Protection')
            axes[0,1].set_title('Protection Status', fontweight='bold')
            axes[0,1].set_ylabel('Status (0=Off, 1=On)')
            axes[0,1].set_ylim(-0.1, 1.1)
            axes[0,1].legend()
            axes[0,1].grid(True, alpha=0.3)
        
        # Threat Activity
        if 'suspicious_activity_count' in df.columns and 'vulnerability_count' in df.columns:
            axes[1,0].bar(df['timestamp'], df['suspicious_activity_count'], alpha=0.7, color='#e67e22', 
                         width=0.8*(df['timestamp'].iloc[1] - df['timestamp'].iloc[0]) if len(df) > 1 else 1, 
                         label='Suspicious Activity')
            axes[1,0].bar(df['timestamp'], df['vulnerability_count'], alpha=0.7, color='#c0392b', 
                         width=0.8*(df['timestamp'].iloc[1] - df['timestamp'].iloc[0]) if len(df) > 1 else 1,
                         bottom=df['suspicious_activity_count'], label='Vulnerabilities')
            axes[1,0].set_title('Security Issues Detected', fontweight='bold')
            axes[1,0].set_ylabel('Count')
            axes[1,0].legend()
            axes[1,0].grid(True, alpha=0.3)
        
        # Security Software Count
        if 'security_software_count' in df.columns:
            axes[1,1].plot(df['timestamp'], df['security_software_count'], color='#8e44ad', linewidth=2, marker='o', markersize=4)
            axes[1,1].fill_between(df['timestamp'], df['security_software_count'], alpha=0.3, color='#8e44ad')
            axes[1,1].set_title('Security Software Running', fontweight='bold')
            axes[1,1].set_ylabel('Count')
            axes[1,1].grid(True, alpha=0.3)
        
        # Format x-axis for all subplots
        for ax in axes.flat:
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
            ax.xaxis.set_major_locator(mdates.HourLocator(interval=max(1, len(df)//10)))
            plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        plt.tight_layout()
        security_file = os.path.join(self.charts_dir, f"security_analysis_{computer_name}_{timestamp}.png")
        plt.savefig(security_file, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"🛡️  Security chart saved: {security_file}")
    
    def save_continuous_data(self):
        """Save data with security information to files"""
        if not self.data_log:
            return
        
        # File paths with security data
        combined_csv = os.path.join(self.data_dir, f"system_security_{self.computer_name}_combined.csv")
        combined_json = os.path.join(self.data_dir, f"system_security_{self.computer_name}_combined.json")
        global_csv = os.path.join(self.data_dir, "system_security_all_computers.csv")
        
        try:
            # Check if CSV file exists
            file_exists = os.path.exists(combined_csv)
            
            with open(combined_csv, 'a', newline='') as f:
                writer = csv.writer(f)
                
                # Headers with security fields
                if not file_exists:
                    headers = [
                        'timestamp', 'computer_name', 'computer_id', 'os_system',
                        'cpu_percent', 'memory_percent', 'memory_used_gb', 'memory_total_gb',
                        'disk_percent', 'disk_free_gb', 'disk_total_gb', 'process_count',
                        'temperature', 'uptime_hours', 'network_sent_mb', 'network_recv_mb',
                        'security_score', 'antivirus_enabled', 'real_time_protection',
                        'definition_age_days', 'suspicious_activity_count', 'vulnerability_count',
                        'security_software_count'
                    ]
                    writer.writerow(headers)
                    print(f"📄 Created new security monitoring file: {combined_csv}")
                
                # Write latest data with security info
                latest_data = self.data_log[-1]
                security = latest_data.get("security", {})
                
                row = [
                    latest_data['timestamp'],
                    latest_data['computer_info']['computer_name'],
                    latest_data['computer_info']['computer_id'],
                    latest_data['computer_info']['os_system'],
                    latest_data['cpu']['usage_percent'],
                    latest_data['memory']['usage_percent'],
                    latest_data['memory']['used_gb'],
                    latest_data['memory']['total_gb'],
                    latest_data['disk']['usage_percent'],
                    latest_data['disk']['free_gb'],
                    latest_data['disk']['total_gb'],
                    latest_data['system']['process_count'],
                    latest_data['system']['temperature_celsius'] or 0,
                    latest_data['system']['uptime_hours'],
                    latest_data['network']['bytes_sent'] / (1024**2),
                    latest_data['network']['bytes_received'] / (1024**2),
                    security.get('security_score', 0),
                    security.get('antivirus_status', {}).get('antivirus_enabled', False),
                    security.get('antivirus_status', {}).get('real_time_protection', False),
                    security.get('antivirus_status', {}).get('definition_age_days', 0),
                    len(security.get('suspicious_activity', [])),
                    len(security.get('vulnerabilities', [])),
                    len(security.get('security_software', []))
                ]
                writer.writerow(row)
            
            # Save to global file
            global_file_exists = os.path.exists(global_csv)
            with open(global_csv, 'a', newline='') as f:
                writer = csv.writer(f)
                if not global_file_exists:
                    writer.writerow(headers)
                writer.writerow(row)
            
            # Save complete JSON
            with open(combined_json, 'w') as f:
                json.dump(self.data_log, f, indent=2)
            
            print(f"💾 Updated security files: {len(self.data_log)} records from {self.computer_name}")
            
        except Exception as e:
            print(f"❌ Error saving security data: {e}")
    
    def collect_data_continuously(self, duration_minutes=5, interval_seconds=30):
        """Collect data with security monitoring"""
        print(f"\n🛡️ SECURITY-ENHANCED DATA COLLECTION for {duration_minutes} minutes")
        print(f"   🖥️  Computer: {self.computer_name}")
        print(f"   ⏱️  Sampling every {interval_seconds} seconds")
        print(f"   🔍 Security scans every {self.security_scan_interval/60:.1f} minutes")
        print(f"   💾 Saving to: {self.data_dir}")
        print("   Press Ctrl+C to stop early\n")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        try:
            while time.time() < end_time:
                # Collect current data with security scan
                current_data = self.get_current_status()
                self.data_log.append(current_data)
                
                # Display current status
                self.display_current_status(current_data)
                
                # Save data
                self.save_continuous_data()
                
                # Wait for next interval
                print(f"💤 Waiting {interval_seconds} seconds until next reading...")
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            print("\n⏹️  Data collection stopped by user")
        
        print(f"\n✅ Security-enhanced collection complete! Gathered {len(self.data_log)} samples")
    
    def run_security_scan_only(self):
        """Run a comprehensive security scan and display results"""
        print("\n🔍 Running comprehensive security scan...")
        print("=" * 60)
        
        security_data = self.perform_security_scan(force=True)
        
        if not security_data:
            print("❌ Security scan failed")
            return
        
        print(f"🛡️  SECURITY SCAN RESULTS - {self.computer_name}")
        print(f"📅 Scan completed: {security_data['scan_timestamp']}")
        print(f"⏱️  Scan duration: {security_data['scan_duration_seconds']} seconds")
        print()
        
        # Overall security score
        score = security_data["security_score"]
        if score >= 90:
            print(f"🟢 Overall Security Score: {score}/100 - EXCELLENT")
        elif score >= 75:
            print(f"🟡 Overall Security Score: {score}/100 - GOOD")
        elif score >= 60:
            print(f"🟠 Overall Security Score: {score}/100 - FAIR")
        else:
            print(f"🔴 Overall Security Score: {score}/100 - POOR")
        
        print("\n📋 DETAILED FINDINGS:")
        print("-" * 40)
        
        # Antivirus status
        av = security_data["antivirus_status"]
        print(f"🦠 Antivirus Protection:")
        print(f"   Enabled: {'✅' if av['antivirus_enabled'] else '❌'}")
        print(f"   Real-time Protection: {'✅' if av['real_time_protection'] else '❌'}")
        if av['definition_age_days'] is not None:
            age_status = "✅" if av['definition_age_days'] <= 1 else "⚠️" if av['definition_age_days'] <= 7 else "❌"
            print(f"   Definition Age: {age_status} {av['definition_age_days']} days")
        
        # Security software
        if security_data["security_software"]:
            print(f"\n🛡️  Detected Security Software ({len(security_data['security_software'])}):")
            for software in security_data["security_software"]:
                print(f"   ✅ {software['software_name']} (PID: {software['pid']})")
        
        # Suspicious activity
        if security_data["suspicious_activity"]:
            print(f"\n⚠️  Suspicious Activity ({len(security_data['suspicious_activity'])}):")
            for activity in security_data["suspicious_activity"]:
                severity_emoji = {"high": "🔴", "medium": "🟡", "low": "🟠"}.get(activity["severity"], "⚠️")
                print(f"   {severity_emoji} {activity['type'].replace('_', ' ').title()}")
        
        # Vulnerabilities
        if security_data["vulnerabilities"]:
            print(f"\n🚨 Security Vulnerabilities ({len(security_data['vulnerabilities'])}):")
            for vuln in security_data["vulnerabilities"]:
                severity_emoji = {"high": "🔴", "medium": "🟡", "low": "🟠"}.get(vuln["severity"], "⚠️")
                print(f"   {severity_emoji} {vuln['type'].replace('_', ' ').title()}")
                if vuln["type"] == "pending_windows_updates":
                    print(f"      → {vuln['count']} pending updates")
        
        print("=" * 60)

def main():
    """Main function for security-enhanced monitoring with visualization"""
    monitor = SecurityEnhancedSystemMonitor()
    
    while True:
        print(f"\n🛡️ Security-Enhanced System Monitor with Data Visualization")
        print(f"🖥️  Computer: {monitor.computer_name}")
        print(f"📁 Data Directory: {monitor.data_dir}")
        print(f"📊 Charts Directory: {monitor.charts_dir}")
        print("=" * 80)
        
        print("\nWhat would you like to do?")
        print("1. 📊 Check current system status")
        print("2. 🔄 Collect data with security monitoring")
        print("3. 🔍 Run comprehensive security scan")
        print("4. 📈 Analyze collected data")
        print("5. 📊 Create comprehensive charts and visualizations")
        print("6. 💾 Save current session to files")
        print("7. 📁 View data directory contents")
        print("8. 🛡️ Security settings and configuration")
        print("9. 🚪 Exit")
        
        choice = input("\nEnter choice (1-9): ").strip()
        
        if choice == '1':
            current_data = monitor.get_current_status()
            monitor.display_current_status(current_data)
        
        elif choice == '2':
            duration = input("Duration in minutes (default 10): ").strip()
            duration = int(duration) if duration.isdigit() else 10
            
            interval = input("Interval in seconds (default 60): ").strip()
            interval = int(interval) if interval.isdigit() else 60
            
            monitor.collect_data_continuously(duration, interval)
        
        elif choice == '3':
            monitor.run_security_scan_only()
        
        elif choice == '4':
            # Simple analysis of collected data
            if not monitor.data_log:
                print("❌ No data collected yet. Use option 2 to collect data first.")
            else:
                print(f"\n📈 SECURITY DATA ANALYSIS - {len(monitor.data_log)} samples")
                print("=" * 60)
                
                # Security score analysis
                security_scores = []
                antivirus_enabled_count = 0
                threat_detections = 0
                
                for data in monitor.data_log:
                    if "security" in data and not data["security"].get("cached"):
                        security = data["security"]
                        security_scores.append(security["security_score"])
                        
                        if security["antivirus_status"]["antivirus_enabled"]:
                            antivirus_enabled_count += 1
                        
                        threat_detections += len(security["suspicious_activity"])
                
                if security_scores:
                    avg_score = sum(security_scores) / len(security_scores)
                    min_score = min(security_scores)
                    max_score = max(security_scores)
                    
                    print(f"🛡️  Security Score Trend:")
                    print(f"   Average: {avg_score:.1f}/100")
                    print(f"   Range: {min_score:.1f} - {max_score:.1f}")
                    
                    print(f"\n🦠 Antivirus Status:")
                    print(f"   Enabled: {antivirus_enabled_count}/{len(security_scores)} samples")
                    
                    print(f"\n⚠️  Threat Activity:")
                    print(f"   Total detections: {threat_detections}")
                    print(f"   Average per sample: {threat_detections/len(security_scores):.1f}")
                else:
                    print("❌ No security scan data available in collected samples")
        
        elif choice == '5':
            # Create comprehensive charts
            print("\n📊 CHART CREATION OPTIONS")
            print("1. Create charts for current computer")
            print("2. Create charts for a specific computer")
            print("3. List available computers")
            
            chart_choice = input("Enter choice (1-3): ").strip()
            
            if chart_choice == '1':
                monitor.create_comprehensive_charts()
            
            elif chart_choice == '2':
                computer_name = input("Enter computer name: ").strip()
                if computer_name:
                    monitor.create_comprehensive_charts(computer_name)
                else:
                    print("❌ Invalid computer name")
            
            elif chart_choice == '3':
                # List available computers from CSV files
                try:
                    csv_files = [f for f in os.listdir(monitor.data_dir) if f.endswith('.csv')]
                    computers = set()
                    for csv_file in csv_files:
                        # Extract computer name from filename
                        parts = csv_file.replace('.csv', '').split('_')
                        for i, part in enumerate(parts):
                            if part == 'security' and i + 1 < len(parts):
                                computers.add(parts[i + 1])
                    
                    if computers:
                        print(f"\n📋 Available computers:")
                        for computer in sorted(computers):
                            print(f"   🖥️  {computer}")
                    else:
                        print("❌ No computer data files found")
                except Exception as e:
                    print(f"❌ Error listing computers: {e}")
        
        elif choice == '6':
            # Save timestamped files
            if not monitor.data_log:
                print("❌ No data to save")
            else:
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                
                # Save detailed security data
                json_filename = os.path.join(monitor.data_dir, f"security_data_{monitor.computer_name}_{timestamp}.json")
                csv_filename = os.path.join(monitor.data_dir, f"security_data_{monitor.computer_name}_{timestamp}.csv")
                
                try:
                    # Save JSON
                    with open(json_filename, 'w') as f:
                        json.dump(monitor.data_log, f, indent=2)
                    print(f"💾 Saved detailed security data to {json_filename}")
                    
                    # Save CSV summary
                    with open(csv_filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        
                        # Headers
                        headers = [
                            'timestamp', 'computer_name', 'cpu_percent', 'memory_percent',
                            'disk_percent', 'security_score', 'antivirus_enabled',
                            'real_time_protection', 'suspicious_count', 'vulnerability_count'
                        ]
                        writer.writerow(headers)
                        
                        # Data rows
                        for data in monitor.data_log:
                            security = data.get("security", {})
                            row = [
                                data['timestamp'],
                                data['computer_info']['computer_name'],
                                data['cpu']['usage_percent'],
                                data['memory']['usage_percent'],
                                data['disk']['usage_percent'],
                                security.get('security_score', 0),
                                security.get('antivirus_status', {}).get('antivirus_enabled', False),
                                security.get('antivirus_status', {}).get('real_time_protection', False),
                                len(security.get('suspicious_activity', [])),
                                len(security.get('vulnerabilities', []))
                            ]
                            writer.writerow(row)
                    
                    print(f"📊 Saved security summary to {csv_filename}")
                    
                    # Ask if user wants to create charts
                    create_charts = input("\nWould you like to create charts for this data? (y/n): ").strip().lower()
                    if create_charts == 'y':
                        monitor.create_comprehensive_charts()
                    
                except Exception as e:
                    print(f"❌ Error saving files: {e}")
        
        elif choice == '7':
            print(f"\n📁 Contents of {monitor.data_dir}:")
            print(f"📊 Contents of {monitor.charts_dir}:")
            try:
                # Data files
                data_files = os.listdir(monitor.data_dir)
                if data_files:
                    security_files = [f for f in data_files if 'security' in f.lower()]
                    other_files = [f for f in data_files if 'security' not in f.lower()]
                    
                    if security_files:
                        print(f"\n   🛡️  Security Data Files:")
                        for file in sorted(security_files):
                            file_path = os.path.join(monitor.data_dir, file)
                            size = os.path.getsize(file_path)
                            modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                            print(f"      📄 {file} ({size:,} bytes, {modified.strftime('%Y-%m-%d %H:%M')})")
                    
                    if other_files:
                        print(f"\n   📊 Other Data Files:")
                        for file in sorted(other_files):
                            file_path = os.path.join(monitor.data_dir, file)
                            size = os.path.getsize(file_path)
                            modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                            print(f"      📄 {file} ({size:,} bytes, {modified.strftime('%Y-%m-%d %H:%M')})")
                else:
                    print("   📂 Data directory is empty")
                
                # Chart files
                if os.path.exists(monitor.charts_dir):
                    chart_files = os.listdir(monitor.charts_dir)
                    if chart_files:
                        print(f"\n   📊 Chart Files:")
                        for file in sorted(chart_files):
                            if file.endswith(('.png', '.jpg', '.jpeg')):
                                file_path = os.path.join(monitor.charts_dir, file)
                                size = os.path.getsize(file_path)
                                modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                                print(f"      🖼️  {file} ({size:,} bytes, {modified.strftime('%Y-%m-%d %H:%M')})")
                    else:
                        print("   📂 Charts directory is empty")
                        
            except Exception as e:
                print(f"   ❌ Error reading directories: {e}")
        
        elif choice == '8':
            print(f"\n🛡️ SECURITY CONFIGURATION")
            print("=" * 50)
            print(f"Current scan interval: {monitor.security_scan_interval/60:.1f} minutes")
            print(f"Computer ID: {monitor.computer_name}")
            print(f"Operating System: {platform.system()} {platform.release()}")
            
            print("\nSecurity Settings:")
            print("1. Change security scan interval")
            print("2. Force security scan cache refresh")
            print("3. View detected security software")
            print("4. Back to main menu")
            
            sub_choice = input("\nEnter choice (1-4): ").strip()
            
            if sub_choice == '1':
                try:
                    new_interval = float(input("New scan interval in minutes (current: {:.1f}): ".format(monitor.security_scan_interval/60)))
                    monitor.security_scan_interval = int(new_interval * 60)
                    print(f"✅ Scan interval updated to {new_interval:.1f} minutes")
                except ValueError:
                    print("❌ Invalid input. Please enter a number.")
            
            elif sub_choice == '2':
                monitor.last_security_scan = None
                print("✅ Security scan cache cleared. Next status check will run a fresh scan.")
            
            elif sub_choice == '3':
                security_software = monitor.check_running_security_software()
                if security_software:
                    print(f"\n🛡️  Detected Security Software ({len(security_software)}):")
                    for software in security_software:
                        print(f"   ✅ {software['software_name']} (Process: {software['process_name']}, PID: {software['pid']})")
                else:
                    print("❌ No recognized security software detected")
            
            elif sub_choice == '4':
                continue
        
        elif choice == '9':
            print("👋 Goodbye! Stay secure!")
            break
        
        else:
            print("❌ Invalid choice, please try again")

if __name__ == "__main__":
    main()