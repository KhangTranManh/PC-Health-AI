#!/usr/bin/env python3
"""
Portable System Security Monitor
Standalone executable for system monitoring without Python
File: portable_monitor.py
"""

import psutil
import platform
import datetime
import time
import json
import csv
import os
import socket
import subprocess
import sys
from pathlib import Path

class PortableSystemMonitor:
    """Lightweight portable system monitor for data collection"""
    
    def __init__(self):
        self.computer_name = self.get_computer_identifier()
        self.data_dir = "monitor_data"
        self.ensure_data_directory()
        print(f"🖥️  Portable Monitor - {self.computer_name}")
        print(f"📁 Data: {os.path.abspath(self.data_dir)}")
    
    def get_computer_identifier(self):
        """Get unique computer identifier"""
        try:
            hostname = socket.gethostname()
            os_name = platform.system()
            clean_name = hostname.replace(" ", "_").replace("-", "_")
            return f"{clean_name}_{os_name}"
        except Exception:
            return f"Unknown_{datetime.datetime.now().strftime('%Y%m%d')}"
    
    def ensure_data_directory(self):
        """Create data directory"""
        try:
            os.makedirs(self.data_dir, exist_ok=True)
        except Exception as e:
            print(f"❌ Error creating directory: {e}")
            self.data_dir = "."
    
    def check_security_basic(self):
        """Basic security check - Windows only"""
        security_info = {
            "antivirus_enabled": True,  # Default assume enabled
            "real_time_protection": True,
            "definition_age_days": 0,
            "security_center_status": "unknown"
        }
        
        if platform.system() != "Windows":
            return security_info
        
        try:
            # Simple Windows Defender check
            result = subprocess.run([
                "powershell", "-Command", 
                "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json"
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout:
                import json
                status = json.loads(result.stdout)
                security_info["antivirus_enabled"] = status.get("AntivirusEnabled", True)
                security_info["real_time_protection"] = status.get("RealTimeProtectionEnabled", True)
                security_info["security_center_status"] = "active"
        except Exception:
            pass  # Keep defaults
        
        return security_info
    
    def get_system_snapshot(self):
        """Get single system snapshot"""
        try:
            timestamp = datetime.datetime.now()
            
            # Basic system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Network
            try:
                network = psutil.net_io_counters()
                net_sent_mb = network.bytes_sent / (1024**2)
                net_recv_mb = network.bytes_recv / (1024**2)
            except:
                net_sent_mb = net_recv_mb = 0
            
            # Process count
            try:
                process_count = len(psutil.pids())
            except:
                process_count = 0
            
            # Temperature
            temperature = 0
            try:
                temps = psutil.sensors_temperatures()
                if temps:
                    temp_values = list(temps.values())[0]
                    if temp_values:
                        temperature = temp_values[0].current
            except:
                pass
            
            # Battery
            battery_percent = None
            try:
                battery = psutil.sensors_battery()
                if battery:
                    battery_percent = battery.percent
            except:
                pass
            
            # Uptime
            try:
                uptime_hours = (time.time() - psutil.boot_time()) / 3600
            except:
                uptime_hours = 0
            
            # Security check
            security = self.check_security_basic()
            
            # Calculate simple security score
            security_score = 100
            if not security["antivirus_enabled"]:
                security_score -= 30
            if not security["real_time_protection"]:
                security_score -= 20
            
            # Check for high resource usage (basic threats)
            suspicious_count = 0
            vulnerability_count = 0
            
            if cpu_percent > 90:
                suspicious_count += 1
            if memory.percent > 95:
                vulnerability_count += 1
            if hasattr(disk, 'percent') and disk.used/disk.total * 100 > 95:
                vulnerability_count += 1
            
            # Compile data
            data = {
                "timestamp": timestamp.isoformat(),
                "computer_name": socket.gethostname(),
                "computer_id": self.computer_name,
                "os_system": platform.system(),
                "cpu_percent": round(cpu_percent, 1),
                "memory_percent": round(memory.percent, 1),
                "memory_used_gb": round(memory.used / (1024**3), 2),
                "memory_total_gb": round(memory.total / (1024**3), 2),
                "disk_percent": round((disk.used / disk.total) * 100, 1),
                "disk_free_gb": round(disk.free / (1024**3), 2),
                "disk_total_gb": round(disk.total / (1024**3), 2),
                "process_count": process_count,
                "temperature": int(temperature) if temperature else 0,
                "uptime_hours": round(uptime_hours, 2),
                "network_sent_mb": round(net_sent_mb, 2),
                "network_recv_mb": round(net_recv_mb, 2),
                "security_score": security_score,
                "antivirus_enabled": security["antivirus_enabled"],
                "real_time_protection": security["real_time_protection"],
                "definition_age_days": security["definition_age_days"],
                "suspicious_activity_count": suspicious_count,
                "vulnerability_count": vulnerability_count,
                "security_software_count": 1 if security["antivirus_enabled"] else 0,
                "battery_percent": battery_percent
            }
            
            return data
            
        except Exception as e:
            print(f"❌ Error collecting data: {e}")
            return None
    
    def save_data(self, data):
        """Save data to CSV file"""
        if not data:
            return False
        
        csv_file = os.path.join(self.data_dir, f"monitor_{self.computer_name}.csv")
        
        try:
            # Check if file exists
            file_exists = os.path.exists(csv_file)
            
            with open(csv_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=data.keys())
                
                if not file_exists:
                    writer.writeheader()
                
                writer.writerow(data)
            
            return True
        except Exception as e:
            print(f"❌ Error saving data: {e}")
            return False
    
    def display_status(self, data):
        """Display current status"""
        if not data:
            return
        
        print(f"\n⏰ {data['timestamp'][:19]}")
        print(f"🖥️  CPU: {data['cpu_percent']}% | Memory: {data['memory_percent']}% | Disk: {data['disk_percent']}%")
        print(f"🔒 Security: {data['security_score']}/100 | AV: {'✅' if data['antivirus_enabled'] else '❌'}")
        
        if data['battery_percent']:
            print(f"🔋 Battery: {data['battery_percent']}%")
    
    def run_single_check(self):
        """Run single system check"""
        print("\n🔍 Collecting system data...")
        data = self.get_system_snapshot()
        
        if data:
            self.display_status(data)
            if self.save_data(data):
                print(f"💾 Data saved to: monitor_{self.computer_name}.csv")
            else:
                print("❌ Failed to save data")
        else:
            print("❌ Failed to collect data")
    
    def run_continuous(self, duration_minutes=10, interval_seconds=60):
        """Run continuous monitoring"""
        print(f"\n🔄 Continuous monitoring for {duration_minutes} minutes")
        print(f"📊 Sampling every {interval_seconds} seconds")
        print("Press Ctrl+C to stop early\n")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        count = 0
        
        try:
            while time.time() < end_time:
                data = self.get_system_snapshot()
                
                if data:
                    count += 1
                    print(f"📝 Sample {count}:", end=" ")
                    self.display_status(data)
                    
                    if self.save_data(data):
                        print(f"   ✅ Saved")
                    else:
                        print(f"   ❌ Save failed")
                else:
                    print("❌ Data collection failed")
                
                # Wait for next interval
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            print(f"\n⏹️  Stopped by user after {count} samples")
        
        print(f"\n✅ Monitoring complete! Collected {count} samples")
        csv_file = os.path.join(self.data_dir, f"monitor_{self.computer_name}.csv")
        if os.path.exists(csv_file):
            print(f"📁 Data file: {os.path.abspath(csv_file)}")

def main():
    """Main function"""
    print("🚀 Portable System Monitor")
    print("=" * 50)
    
    # Check if running as standalone exe
    if getattr(sys, 'frozen', False):
        print("🎯 Running as standalone executable")
    else:
        print("🐍 Running with Python")
    
    monitor = PortableSystemMonitor()
    
    while True:
        print(f"\n📋 Options:")
        print("1. 📊 Single system check")
        print("2. 🔄 Continuous monitoring")
        print("3. 📁 Show data files")
        print("4. 🚪 Exit")
        
        try:
            choice = input("\nEnter choice (1-4): ").strip()
            
            if choice == '1':
                monitor.run_single_check()
            
            elif choice == '2':
                try:
                    duration = input("Duration in minutes (default 10): ").strip()
                    duration = int(duration) if duration.isdigit() else 10
                    
                    interval = input("Interval in seconds (default 60): ").strip()
                    interval = int(interval) if interval.isdigit() else 60
                    
                    monitor.run_continuous(duration, interval)
                except ValueError:
                    print("❌ Invalid input. Using defaults.")
                    monitor.run_continuous()
            
            elif choice == '3':
                print(f"\n📁 Data directory: {os.path.abspath(monitor.data_dir)}")
                try:
                    files = [f for f in os.listdir(monitor.data_dir) if f.endswith('.csv')]
                    if files:
                        print("📄 CSV files:")
                        for file in files:
                            file_path = os.path.join(monitor.data_dir, file)
                            size = os.path.getsize(file_path)
                            print(f"   {file} ({size:,} bytes)")
                    else:
                        print("📂 No CSV files found")
                except Exception as e:
                    print(f"❌ Error reading directory: {e}")
            
            elif choice == '4':
                print("👋 Goodbye!")
                break
            
            else:
                print("❌ Invalid choice")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()