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

class SecurityEnhancedSystemMonitor:
    """System monitor with built-in security scanning capabilities"""
    
    def __init__(self):
        print("🛡️ Security-Enhanced System Monitor Starting...")
        
        # Get computer identification
        self.computer_name = self.get_computer_identifier()
        print(f"🏷️  Computer ID: {self.computer_name}")
        
        # Set up data directory (relative to script location)
        self.data_dir = "data"
        self.ensure_data_directory()
        
        self.data_log = []
        
        # Security scan cache
        self.last_security_scan = None
        self.security_scan_interval = 300  # 5 minutes between full scans
    
    def get_computer_identifier(self):
        """Get a unique identifier for this computer"""
        try:
            hostname = socket.gethostname()
            os_name = platform.system()
            clean_name = hostname.replace(" ", "_").replace("-", "_")
            computer_id = f"{clean_name}_{os_name}"
            return computer_id
        except Exception as e:
            print(f"⚠️  Error getting computer name: {e}")
            return f"Unknown_Computer_{datetime.datetime.now().strftime('%Y%m%d')}"
    
    def ensure_data_directory(self):
        """Create data directory if it doesn't exist"""
        try:
            if not os.path.exists(self.data_dir):
                os.makedirs(self.data_dir)
                print(f"✅ Created data directory: {self.data_dir}")
            else:
                print(f"✅ Using existing data directory: {self.data_dir}")
        except Exception as e:
            print(f"❌ Error creating data directory: {e}")
            self.data_dir = "."
    
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
    """Main function for security-enhanced monitoring"""
    monitor = SecurityEnhancedSystemMonitor()
    
    while True:
        print(f"\n🛡️ Security-Enhanced System Monitor")
        print(f"🖥️  Computer: {monitor.computer_name}")
        print(f"📁 Data Directory: {monitor.data_dir}")
        print("=" * 70)
        
        print("\nWhat would you like to do?")
        print("1. 📊 Check current system status")
        print("2. 🔄 Collect data with security monitoring")
        print("3. 🔍 Run comprehensive security scan")
        print("4. 📈 Analyze collected data")
        print("5. 💾 Save current session to files")
        print("6. 📁 View data directory contents")
        print("7. 🛡️ Security settings and configuration")
        print("8. 🚪 Exit")
        
        choice = input("\nEnter choice (1-8): ").strip()
        
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
                    
                except Exception as e:
                    print(f"❌ Error saving files: {e}")
        
        elif choice == '6':
            print(f"\n📁 Contents of {monitor.data_dir}:")
            try:
                files = os.listdir(monitor.data_dir)
                if files:
                    # Group security files
                    security_files = [f for f in files if 'security' in f.lower()]
                    other_files = [f for f in files if 'security' not in f.lower()]
                    
                    if security_files:
                        print(f"\n   🛡️  Security Files:")
                        for file in sorted(security_files):
                            file_path = os.path.join(monitor.data_dir, file)
                            size = os.path.getsize(file_path)
                            modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                            print(f"      📄 {file} ({size:,} bytes, {modified.strftime('%Y-%m-%d %H:%M')})")
                    
                    if other_files:
                        print(f"\n   📊 Other Monitoring Files:")
                        for file in sorted(other_files):
                            file_path = os.path.join(monitor.data_dir, file)
                            size = os.path.getsize(file_path)
                            modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                            print(f"      📄 {file} ({size:,} bytes, {modified.strftime('%Y-%m-%d %H:%M')})")
                else:
                    print("   📂 Directory is empty")
            except Exception as e:
                print(f"   ❌ Error reading directory: {e}")
        
        elif choice == '7':
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
        
        elif choice == '8':
            print("👋 Goodbye! Stay secure!")
            break
        
        else:
            print("❌ Invalid choice, please try again")

if __name__ == "__main__":
    main()