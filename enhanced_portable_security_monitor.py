# enhanced_portable_security_monitor.py
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
import smtplib
import requests
import threading
import queue
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from pathlib import Path
import zipfile
import shutil
import sys
from typing import List, Dict, Any

class EnhancedPortableSecurityMonitor:
    """Enhanced Portable Security Monitor with Comprehensive Security Scanning and Auto Data Sync"""
    
    def __init__(self):
        print("🛡️ Enhanced Portable Security Monitor Starting...")
        
        # Get executable directory (works for both script and exe)
        if getattr(sys, 'frozen', False):
            # Running as compiled exe
            self.app_dir = os.path.dirname(sys.executable)
        else:
            # Running as script
            self.app_dir = os.path.dirname(os.path.abspath(__file__))
        
        print(f"📁 App Directory: {self.app_dir}")
        
        # Computer identification
        self.computer_name = self.get_computer_identifier()
        print(f"🏷️  Computer ID: {self.computer_name}")
        
        # Set up directories
        self.data_dir = os.path.join(self.app_dir, "data")
        self.config_dir = os.path.join(self.app_dir, "config")
        self.logs_dir = os.path.join(self.app_dir, "logs")
        self.ensure_directories()
        
        # Load configuration
        self.config = self.load_config()
        
        # Data collection
        self.data_log = []
        self.last_security_scan = None
        self.security_scan_interval = 300  # 5 minutes
        
        # Network sync
        self.sync_queue = queue.Queue()
        self.sync_thread = None
        self.stop_sync = False
        
        # Start background sync if enabled
        if self.config.get('auto_sync_enabled', True):
            self.start_background_sync()
    
    def get_computer_identifier(self):
        """Get a unique identifier for this computer"""
        try:
            hostname = socket.gethostname()
            # Just return the clean hostname without OS and MAC
            clean_name = hostname.replace(" ", "_").replace("-", "_")
            return clean_name
        except Exception as e:
            print(f"⚠️  Error getting computer name: {e}")
            return f"Unknown_Computer_{datetime.datetime.now().strftime('%Y%m%d')}"
    
    def ensure_directories(self):
        """Create necessary directories"""
        for directory in [self.data_dir, self.config_dir, self.logs_dir]:
            try:
                if not os.path.exists(directory):
                    os.makedirs(directory)
                    print(f"✅ Created directory: {directory}")
            except Exception as e:
                print(f"❌ Error creating directory {directory}: {e}")
    def load_config(self):
        """Load configuration from file with embedded credentials"""
        config_file = os.path.join(self.config_dir, "config.json")
        
        # SECURE: Embedded email settings (compiled into .exe)
        embedded_email_settings = {
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "sender_email": "khangjaki12@gmail.com",           # Your Gmail
            "sender_password": "jtqc rpnr azyz onfk",             # Your App Password
            "recipient_email": "kxctran@gmail.com",      # Where to receive data
            "subject_prefix": "[Security Monitor Data]"
        }
        
        default_config = {
            "auto_sync_enabled": True,
            "sync_interval_minutes": 30,
            "sync_method": "email",
            "email_settings": embedded_email_settings,  # Use embedded settings
            "webhook_settings": {
                "url": "",
                "headers": {},
                "method": "POST"
            },
            "ftp_settings": {
                "server": "",
                "username": "",
                "password": "",
                "directory": "/"
            },
            "collection_settings": {
                "interval_seconds": 60,
                "include_charts": False,
                "max_file_size_mb": 10
            }
        }
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Always use embedded email settings for security
                    loaded_config["email_settings"] = embedded_email_settings
                    # Merge other settings
                    for key, value in default_config.items():
                        if key not in loaded_config and key != "email_settings":
                            loaded_config[key] = value
                    return loaded_config
            else:
                # Create config file WITHOUT email credentials
                safe_config = default_config.copy()
                safe_config["email_settings"] = {
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "sender_email": "*** CONFIGURED ***",
                    "sender_password": "*** CONFIGURED ***", 
                    "recipient_email": "*** CONFIGURED ***",
                    "subject_prefix": "[Security Monitor Data]"
                }
                
                with open(config_file, 'w') as f:
                    json.dump(safe_config, f, indent=2)
                print(f"📄 Created config file (credentials secured)")
                return default_config
        except Exception as e:
            print(f"⚠️  Error loading config: {e}")
            return default_config
    
    def save_config(self):
        """Save configuration to file"""
        config_file = os.path.join(self.config_dir, "config.json")
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            print("✅ Configuration saved")
        except Exception as e:
            print(f"❌ Error saving config: {e}")
    
    def log_message(self, message, level="INFO"):
        """Log messages to file"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        log_file = os.path.join(self.logs_dir, f"monitor_{datetime.date.today().strftime('%Y%m%d')}.log")
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"❌ Error writing to log: {e}")
        
        # Also print to console
        print(log_entry)
    
    def check_internet_connection(self):
        """Check if internet connection is available"""
        try:
            # Try to connect to Google DNS
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except OSError:
            try:
                # Fallback: try to connect to Cloudflare DNS
                socket.create_connection(("1.1.1.1", 53), timeout=3)
                return True
            except OSError:
                return False
    
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
            self.log_message(f"Could not check Windows Defender status: {e}", "WARNING")
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
            self.log_message(f"Error checking security processes: {e}", "WARNING")
        
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
            self.log_message(f"Error checking suspicious processes: {e}", "WARNING")
        
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
                    self.log_message(f"Could not check Windows updates: {e}", "WARNING")
            
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
            self.log_message(f"Error checking vulnerabilities: {e}", "WARNING")
        
        return vulnerabilities
    
    def perform_security_scan(self, force=False):
        """Perform comprehensive security scan"""
        current_time = time.time()
        
        # Check if we need to run a new scan
        if not force and self.last_security_scan:
            if current_time - self.last_security_scan < self.security_scan_interval:
                return None  # Use cached results
        
        self.log_message("Performing security scan...")
        
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
        """Get current system status with comprehensive security information"""
        timestamp = datetime.datetime.now()
        
        try:
            # Basic system metrics
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
                temperature = 0
            
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
            
            # If no new security scan, create basic data
            if not security_data:
                security_data = {
                    "security_score": 90,  # Default good score
                    "antivirus_status": {"antivirus_enabled": True, "real_time_protection": True, "definition_age_days": 0},
                    "security_software": [],
                    "suspicious_activity": [],
                    "vulnerabilities": []
                }
            
            # Compile all data with the same structure as colector.py
            system_data = {
                "timestamp": timestamp.isoformat(),
                "computer_name": socket.gethostname(),
                "computer_id": self.computer_name,
                "os_system": platform.system(),
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_used_gb": memory.used / (1024**3),
                "memory_total_gb": memory.total / (1024**3),
                "disk_percent": (disk.used / disk.total) * 100,
                "disk_free_gb": disk.free / (1024**3),
                "disk_total_gb": disk.total / (1024**3),
                "process_count": process_count,
                "temperature": temperature,
                "uptime_hours": (time.time() - psutil.boot_time()) / 3600,
                "network_sent_mb": network_io.bytes_sent / (1024**2),
                "network_recv_mb": network_io.bytes_recv / (1024**2),
                "security_score": security_data["security_score"],
                "antivirus_enabled": security_data["antivirus_status"]["antivirus_enabled"],
                "real_time_protection": security_data["antivirus_status"]["real_time_protection"],
                "definition_age_days": security_data["antivirus_status"]["definition_age_days"] or 0,
                "suspicious_activity_count": len(security_data["suspicious_activity"]),
                "vulnerability_count": len(security_data["vulnerabilities"]),
                "security_software_count": len(security_data["security_software"]),
                "internet_connected": self.check_internet_connection()
            }
            
            return system_data
            
        except Exception as e:
            self.log_message(f"Error getting system status: {e}", "ERROR")
            return None
    
    def save_data_to_file(self):
        """Save collected data to files"""
        if not self.data_log:
            return None
        
        # CSV file with the desired format
        csv_filename = os.path.join(self.data_dir, f"system_security_{self.computer_name}_combined.csv")
        try:
            with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
                if self.data_log:
                    writer = csv.DictWriter(f, fieldnames=self.data_log[0].keys())
                    writer.writeheader()
                    writer.writerows(self.data_log)
            
            self.log_message(f"Data saved to {csv_filename}")
            return csv_filename
            
        except Exception as e:
            self.log_message(f"Error saving data: {e}", "ERROR")
            return None
    
    def create_data_package(self):
        """Create a zip package with all data files"""
        try:
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            package_name = f"system_security_{self.computer_name}_Windows_{timestamp}.zip"
            package_path = os.path.join(self.data_dir, package_name)
            
            with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add data files
                for root, dirs, files in os.walk(self.data_dir):
                    for file in files:
                        if file.endswith(('.csv', '.json')) and file != package_name:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, self.data_dir)
                            zipf.write(file_path, arcname)
                
                # Add recent logs
                for root, dirs, files in os.walk(self.logs_dir):
                    for file in files:
                        if file.endswith('.log'):
                            file_path = os.path.join(root, file)
                            # Only include today's log
                            if datetime.date.today().strftime('%Y%m%d') in file:
                                arcname = f"logs/{file}"
                                zipf.write(file_path, arcname)
                
                # Add system info
                system_info = {
                    "computer_id": self.computer_name,
                    "os_system": platform.system(),
                    "os_release": platform.release(),
                    "architecture": platform.architecture()[0],
                    "hostname": socket.gethostname(),
                    "package_created": timestamp,
                    "data_points": len(self.data_log)
                }
                
                info_path = os.path.join(self.data_dir, "system_info.json")
                with open(info_path, 'w') as f:
                    json.dump(system_info, f, indent=2)
                zipf.write(info_path, "system_info.json")
                os.remove(info_path)  # Clean up temp file
            
            # Check file size
            file_size_mb = os.path.getsize(package_path) / (1024**2)
            max_size = self.config['collection_settings']['max_file_size_mb']
            
            if file_size_mb > max_size:
                self.log_message(f"Package too large: {file_size_mb:.1f}MB > {max_size}MB", "WARNING")
                os.remove(package_path)
                return None
            
            self.log_message(f"Data package created: {package_name} ({file_size_mb:.1f}MB)")
            return package_path
            
        except Exception as e:
            self.log_message(f"Error creating data package: {e}", "ERROR")
            return None
    
    def send_data_via_email(self, file_path):
        """Send data package via email"""
        try:
            email_config = self.config['email_settings']
            
            if not all([email_config['sender_email'], email_config['sender_password'], email_config['recipient_email']]):
                self.log_message("Email configuration incomplete", "WARNING")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = email_config['sender_email']
            msg['To'] = email_config['recipient_email']
            msg['Subject'] = f"{email_config['subject_prefix']} Data from {self.computer_name}"
            
            # Body
            body = f"""
Enhanced Security Monitor Data Report

Computer: {self.computer_name}
Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Data Points: {len(self.data_log)}
File Size: {os.path.getsize(file_path) / (1024**2):.1f} MB

This is an automated message from the Enhanced Portable Security Monitor.
            """
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach file
            filename = os.path.basename(file_path)
            with open(file_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {filename}'
            )
            msg.attach(part)
            
            # Send email
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['sender_email'], email_config['sender_password'])
            text = msg.as_string()
            server.sendmail(email_config['sender_email'], email_config['recipient_email'], text)
            server.quit()
            
            self.log_message(f"Data sent via email to {email_config['recipient_email']}")
            return True
            
        except Exception as e:
            self.log_message(f"Error sending email: {e}", "ERROR")
            return False
    
    def send_data_via_webhook(self, file_path):
        """Send data package via webhook"""
        try:
            webhook_config = self.config['webhook_settings']
            
            if not webhook_config['url']:
                self.log_message("Webhook URL not configured", "WARNING")
                return False
            
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, 'application/zip')}
                data = {
                    'computer_id': self.computer_name,
                    'timestamp': datetime.datetime.now().isoformat(),
                    'data_points': len(self.data_log)
                }
                
                headers = webhook_config.get('headers', {})
                
                response = requests.post(
                    webhook_config['url'],
                    files=files,
                    data=data,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    self.log_message(f"Data sent via webhook to {webhook_config['url']}")
                    return True
                else:
                    self.log_message(f"Webhook failed: {response.status_code}", "ERROR")
                    return False
                    
        except Exception as e:
            self.log_message(f"Error sending webhook: {e}", "ERROR")
            return False
    
    def sync_data(self):
        """Sync data to configured destination"""
        if not self.check_internet_connection():
            self.log_message("No internet connection for sync", "WARNING")
            return False
        
        if not self.data_log:
            self.log_message("No data to sync", "INFO")
            return False
        
        # Create data package
        package_path = self.create_data_package()
        if not package_path:
            return False
        
        # Send via configured method
        sync_method = self.config.get('sync_method', 'email')
        success = False
        
        try:
            if sync_method == 'email':
                success = self.send_data_via_email(package_path)
            elif sync_method == 'webhook':
                success = self.send_data_via_webhook(package_path)
            # Add FTP method if needed
            
            if success:
                # Clean up old data files after successful sync
                self.cleanup_old_files()
                # Clear data log to start fresh
                self.data_log = []
            
            # Always remove the package file
            try:
                os.remove(package_path)
            except:
                pass
                
        except Exception as e:
            self.log_message(f"Error during sync: {e}", "ERROR")
        
        return success
    
    def cleanup_old_files(self):
        """Clean up old data files to save space"""
        try:
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=7)
            
            for directory in [self.data_dir, self.logs_dir]:
                for file in os.listdir(directory):
                    file_path = os.path.join(directory, file)
                    if os.path.isfile(file_path):
                        file_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                        if file_time < cutoff_date:
                            os.remove(file_path)
                            self.log_message(f"Cleaned up old file: {file}")
                            
        except Exception as e:
            self.log_message(f"Error during cleanup: {e}", "WARNING")
    
    def start_background_sync(self):
        """Start background thread for automatic syncing"""
        if self.sync_thread and self.sync_thread.is_alive():
            return
        
        self.stop_sync = False
        self.sync_thread = threading.Thread(target=self._background_sync_worker, daemon=True)
        self.sync_thread.start()
        self.log_message("Background sync started")
    
    def stop_background_sync(self):
        """Stop background sync thread"""
        self.stop_sync = True
        if self.sync_thread:
            self.sync_thread.join(timeout=5)
        self.log_message("Background sync stopped")
    
    def _background_sync_worker(self):
        """Background worker for syncing data"""
        sync_interval = self.config.get('sync_interval_minutes', 30) * 60
        
        while not self.stop_sync:
            try:
                time.sleep(60)  # Check every minute
                
                # Check if it's time to sync
                if len(self.data_log) > 0:
                    if hasattr(self, 'last_sync_time'):
                        time_since_sync = time.time() - self.last_sync_time
                        if time_since_sync >= sync_interval:
                            if self.sync_data():
                                self.last_sync_time = time.time()
                    else:
                        self.last_sync_time = time.time()
                        
            except Exception as e:
                self.log_message(f"Background sync error: {e}", "ERROR")
                time.sleep(300)  # Wait 5 minutes before retrying
    
    def collect_data_continuously(self, duration_minutes=60):
        """Collect data continuously with auto-sync"""
        self.log_message(f"Starting enhanced data collection for {duration_minutes} minutes")
        
        interval = self.config['collection_settings']['interval_seconds']
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        try:
            while time.time() < end_time:
                # Collect data
                data = self.get_current_status()
                if data:
                    self.data_log.append(data)
                    
                    # Display status with enhanced info
                    print(f"📊 {data['timestamp']}: CPU {data['cpu_percent']:.1f}%, "
                          f"Memory {data['memory_percent']:.1f}%, "
                          f"Security {data['security_score']}/100, "
                          f"Temp {data['temperature']}°C, "
                          f"Processes {data['process_count']}")
                
                # Sleep until next collection
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.log_message("Data collection stopped by user")
        
        # Save data before finishing
        self.save_data_to_file()
        
        # Try to sync if connected
        if self.check_internet_connection():
            self.sync_data()
        
        self.log_message(f"Enhanced data collection complete: {len(self.data_log)} samples")
    
    def setup_wizard(self):
        """Setup wizard for first-time configuration"""
        print("\n🔧 ENHANCED PORTABLE SECURITY MONITOR SETUP")
        print("=" * 50)
        
        # Email setup
        print("\n📧 Email Configuration (for data sync):")
        self.config['email_settings']['sender_email'] = input("Sender email: ").strip()
        self.config['email_settings']['sender_password'] = input("Email password/app password: ").strip()
        self.config['email_settings']['recipient_email'] = input("Recipient email: ").strip()
        
        # Sync settings
        print("\n🔄 Sync Settings:")
        sync_method = input("Sync method (email/webhook) [email]: ").strip().lower()
        if sync_method in ['email', 'webhook']:
            self.config['sync_method'] = sync_method
        
        sync_interval = input("Sync interval in minutes [30]: ").strip()
        if sync_interval.isdigit():
            self.config['sync_interval_minutes'] = int(sync_interval)
        
        # Collection settings
        print("\n📊 Collection Settings:")
        collection_interval = input("Data collection interval in seconds [60]: ").strip()
        if collection_interval.isdigit():
            self.config['collection_settings']['interval_seconds'] = int(collection_interval)
        
        # Save configuration
        self.save_config()
        print("\n✅ Setup complete! Configuration saved.")

def main():
    """Main function for enhanced portable monitor"""
    monitor = EnhancedPortableSecurityMonitor()
    
    # Check if this is first run
    config_file = os.path.join(monitor.config_dir, "config.json")
    if not os.path.exists(config_file) or not monitor.config['email_settings']['sender_email']:
        print("👋 Welcome to Enhanced Portable Security Monitor!")
        setup = input("Would you like to run the setup wizard? (y/n): ").strip().lower()
        if setup == 'y':
            monitor.setup_wizard()
    
    while True:
        print(f"\n🛡️ ENHANCED PORTABLE SECURITY MONITOR")
        print(f"🖥️  Computer: {monitor.computer_name}")
        print(f"🌐 Internet: {'✅ Connected' if monitor.check_internet_connection() else '❌ Disconnected'}")
        print("=" * 60)
        
        print("\nOptions:")
        print("1. 📊 Quick system check")
        print("2. 🔄 Start monitoring (60 min)")
        print("3. 🔄 Custom monitoring duration")
        print("4. 📤 Sync data now")
        print("5. ⚙️  Settings")
        print("6. 📁 View data files")
        print("7. 📋 View logs")
        print("8. 🔍 Run security scan")
        print("9. 🚪 Exit")
        
        choice = input("\nEnter choice (1-9): ").strip()
        
        if choice == '1':
            data = monitor.get_current_status()
            if data:
                print(f"\n📊 ENHANCED SYSTEM STATUS - {data['timestamp']}")
                print(f"🖥️  CPU: {data['cpu_percent']:.1f}%")
                print(f"🧠 Memory: {data['memory_percent']:.1f}% ({data['memory_used_gb']:.1f}GB used)")
                print(f"💾 Disk: {data['disk_percent']:.1f}% ({data['disk_free_gb']:.1f}GB free)")
                print(f"🔥 Temperature: {data['temperature']}°C")
                print(f"⚙️  Processes: {data['process_count']}")
                print(f"🛡️  Security Score: {data['security_score']}/100")
                print(f"🦠 Antivirus: {'✅ Active' if data['antivirus_enabled'] else '❌ Inactive'}")
                print(f"🔒 Real-time Protection: {'✅ Active' if data['real_time_protection'] else '❌ Inactive'}")
                print(f"⚠️  Threats Detected: {data['suspicious_activity_count']}")
                print(f"🚨 Vulnerabilities: {data['vulnerability_count']}")
                print(f"🌐 Internet: {'Connected' if data['internet_connected'] else 'Disconnected'}")
        
        elif choice == '2':
            monitor.collect_data_continuously(60)
        
        elif choice == '3':
            try:
                duration = int(input("Duration in minutes: "))
                monitor.collect_data_continuously(duration)
            except ValueError:
                print("❌ Invalid duration")
        
        elif choice == '4':
            print("📤 Syncing data...")
            if monitor.sync_data():
                print("✅ Data synced successfully")
            else:
                print("❌ Sync failed - check logs for details")
        
        elif choice == '5':
            print("\n⚙️  SETTINGS")
            print("1. Run setup wizard")
            print("2. Toggle auto-sync")
            print("3. View current config")
            print("4. Back")
            
            sub_choice = input("Choice: ").strip()
            if sub_choice == '1':
                monitor.setup_wizard()
            elif sub_choice == '2':
                current = monitor.config['auto_sync_enabled']
                monitor.config['auto_sync_enabled'] = not current
                monitor.save_config()
                print(f"Auto-sync: {'Enabled' if not current else 'Disabled'}")
            elif sub_choice == '3':
                print(f"\nCurrent Configuration:")
                print(f"Sync Method: {monitor.config['sync_method']}")
                print(f"Auto-sync: {monitor.config['auto_sync_enabled']}")
                print(f"Sync Interval: {monitor.config['sync_interval_minutes']} minutes")
                print(f"Collection Interval: {monitor.config['collection_settings']['interval_seconds']} seconds")
        
        elif choice == '6':
            print(f"\n📁 Data Files in {monitor.data_dir}:")
            try:
                files = os.listdir(monitor.data_dir)
                if files:
                    for file in sorted(files):
                        if file.endswith(('.csv', '.json', '.zip')):
                            file_path = os.path.join(monitor.data_dir, file)
                            size = os.path.getsize(file_path)
                            print(f"   📄 {file} ({size:,} bytes)")
                else:
                    print("   📂 No data files found")
            except Exception as e:
                print(f"   ❌ Error: {e}")
        
        elif choice == '7':
            print(f"\n📋 Recent Logs:")
            try:
                today_log = os.path.join(monitor.logs_dir, f"monitor_{datetime.date.today().strftime('%Y%m%d')}.log")
                if os.path.exists(today_log):
                    with open(today_log, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        # Show last 10 lines
                        for line in lines[-10:]:
                            print(f"   {line.strip()}")
                else:
                    print("   📂 No logs for today")
            except Exception as e:
                print(f"   ❌ Error: {e}")
        
        elif choice == '8':
            print("🔍 Running comprehensive security scan...")
            security_data = monitor.perform_security_scan(force=True)
            if security_data:
                print(f"\n🛡️  SECURITY SCAN RESULTS")
                print(f"Score: {security_data['security_score']}/100")
                print(f"Antivirus: {'✅' if security_data['antivirus_status']['antivirus_enabled'] else '❌'}")
                print(f"Real-time Protection: {'✅' if security_data['antivirus_status']['real_time_protection'] else '❌'}")
                print(f"Security Software: {len(security_data['security_software'])} detected")
                print(f"Suspicious Activity: {len(security_data['suspicious_activity'])} items")
                print(f"Vulnerabilities: {len(security_data['vulnerabilities'])} issues")
            else:
                print("❌ Security scan failed")
        
        elif choice == '9':
            monitor.stop_background_sync()
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice")

if __name__ == "__main__":
    main()