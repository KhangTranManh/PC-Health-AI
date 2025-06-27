import psutil
import platform
import datetime
import time
import json
import csv
import os

class SimpleSystemMonitor:
    """Simple system information collector"""
    
    def __init__(self):
        print("🖥️ System Monitor Starting...")
        
        # Set up data directory
        self.data_dir = r"D:\Bla\data"
        self.ensure_data_directory()
        
        self.data_log = []
    
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
            print("📁 Using current directory instead")
            self.data_dir = "."
    
    def get_basic_system_info(self):
        """Get basic system information (one-time collection)"""
        print("\n📋 BASIC SYSTEM INFORMATION:")
        print("=" * 50)
        
        # Operating System
        print(f"OS: {platform.system()} {platform.release()}")
        print(f"Architecture: {platform.architecture()[0]}")
        print(f"Machine: {platform.machine()}")
        print(f"Processor: {platform.processor()}")
        
        # CPU Information
        print(f"CPU Cores: {psutil.cpu_count(logical=False)} physical, {psutil.cpu_count(logical=True)} logical")
        
        # Memory Information
        memory = psutil.virtual_memory()
        print(f"Total RAM: {memory.total / (1024**3):.2f} GB")
        
        # Disk Information
        disk = psutil.disk_usage('/')
        print(f"Total Disk: {disk.total / (1024**3):.2f} GB")
        
        # Network Interfaces
        network_interfaces = psutil.net_if_addrs()
        print(f"Network Interfaces: {len(network_interfaces)}")
        
        print("=" * 50)
    
    def get_current_status(self):
        """Get current system status (real-time data)"""
        timestamp = datetime.datetime.now()
        
        # CPU Usage
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_freq = psutil.cpu_freq()
        
        # Memory Usage
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Disk Usage
        disk = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        # Network Usage
        network_io = psutil.net_io_counters()
        
        # Process Information
        process_count = len(psutil.pids())
        
        # Temperature (if available)
        temperature = None
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                # Get first available temperature sensor
                temp_sensor = list(temps.values())[0]
                if temp_sensor:
                    temperature = temp_sensor[0].current
        except:
            temperature = None
        
        # Battery (if available)
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
        
        # Compile all data
        system_data = {
            "timestamp": timestamp.isoformat(),
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
                "uptime_hours": time.time() - psutil.boot_time()
            }
        }
        
        return system_data
    
    def display_current_status(self, data):
        """Display current status in a readable format"""
        print(f"\n🕐 STATUS AT: {data['timestamp']}")
        print("=" * 60)
        
        # CPU
        print(f"🖥️  CPU Usage: {data['cpu']['usage_percent']:.1f}%")
        if data['cpu']['frequency_mhz']:
            print(f"   Frequency: {data['cpu']['frequency_mhz']:.0f} MHz")
        
        # Memory
        print(f"🧠 Memory: {data['memory']['used_gb']:.1f}GB / {data['memory']['total_gb']:.1f}GB ({data['memory']['usage_percent']:.1f}%)")
        print(f"   Available: {data['memory']['available_gb']:.1f}GB")
        
        # Disk
        print(f"💾 Disk: {data['disk']['used_gb']:.1f}GB / {data['disk']['total_gb']:.1f}GB ({data['disk']['usage_percent']:.1f}%)")
        print(f"   Free: {data['disk']['free_gb']:.1f}GB")
        
        # Network
        print(f"🌐 Network: ↑{data['network']['bytes_sent']/(1024**2):.1f}MB sent, ↓{data['network']['bytes_received']/(1024**2):.1f}MB received")
        
        # System
        print(f"⚙️  Processes: {data['system']['process_count']}")
        if data['system']['temperature_celsius']:
            print(f"🌡️  Temperature: {data['system']['temperature_celsius']:.1f}°C")
        
        # Battery
        if data['system']['battery']:
            battery = data['system']['battery']
            status = "🔌 Plugged in" if battery['plugged'] else "🔋 On battery"
            print(f"{status}: {battery['percent']:.0f}%")
        
        print("=" * 60)
    
    def collect_data_continuously(self, duration_minutes=5, interval_seconds=30):
        """Collect data continuously for training purposes"""
        print(f"\n📊 COLLECTING DATA FOR {duration_minutes} MINUTES...")
        print(f"   Sampling every {interval_seconds} seconds")
        print(f"   Saving to: {self.data_dir}")
        print("   Press Ctrl+C to stop early\n")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        try:
            while time.time() < end_time:
                # Collect current data
                current_data = self.get_current_status()
                self.data_log.append(current_data)
                
                # Display current status
                self.display_current_status(current_data)
                
                # Save to combined file after each reading
                self.save_continuous_data()
                
                # Wait for next interval
                print(f"💤 Waiting {interval_seconds} seconds until next reading...")
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            print("\n⏹️  Data collection stopped by user")
        
        print(f"\n✅ Data collection complete! Collected {len(self.data_log)} data points")
        print(f"📁 All data saved in: {self.data_dir}")
    
    def save_data_to_files(self):
        """Save collected data to JSON and CSV files in the data directory"""
        if not self.data_log:
            print("❌ No data to save")
            return
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create file paths in the data directory
        json_filename = os.path.join(self.data_dir, f"system_data_{timestamp}.json")
        csv_filename = os.path.join(self.data_dir, f"system_data_{timestamp}.csv")
        
        try:
            # Save to JSON (full data)
            with open(json_filename, 'w') as f:
                json.dump(self.data_log, f, indent=2)
            print(f"💾 Saved full data to {json_filename}")
            
            # Save to CSV (simplified data for easy analysis)
            with open(csv_filename, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Headers
                headers = [
                    'timestamp', 'cpu_percent', 'memory_percent', 'memory_used_gb', 
                    'disk_percent', 'disk_free_gb', 'process_count', 'temperature',
                    'network_sent_mb', 'network_recv_mb'
                ]
                writer.writerow(headers)
                
                # Data rows
                for data in self.data_log:
                    row = [
                        data['timestamp'],
                        data['cpu']['usage_percent'],
                        data['memory']['usage_percent'],
                        data['memory']['used_gb'],
                        data['disk']['usage_percent'],
                        data['disk']['free_gb'],
                        data['system']['process_count'],
                        data['system']['temperature_celsius'] or 0,
                        data['network']['bytes_sent'] / (1024**2),
                        data['network']['bytes_received'] / (1024**2)
                    ]
                    writer.writerow(row)
            
            print(f"📊 Saved CSV data to {csv_filename}")
            
        except Exception as e:
            print(f"❌ Error saving files: {e}")
    
    def save_continuous_data(self):
        """Save data continuously to a single combined file"""
        if not self.data_log:
            return
        
        # Single combined file path
        combined_csv = os.path.join(self.data_dir, "system_monitoring_combined.csv")
        combined_json = os.path.join(self.data_dir, "system_monitoring_combined.json")
        
        try:
            # Check if CSV file exists to determine if we need headers
            file_exists = os.path.exists(combined_csv)
            
            # Append to CSV
            with open(combined_csv, 'a', newline='') as f:
                writer = csv.writer(f)
                
                # Write headers only if file is new
                if not file_exists:
                    headers = [
                        'timestamp', 'cpu_percent', 'memory_percent', 'memory_used_gb', 
                        'disk_percent', 'disk_free_gb', 'process_count', 'temperature',
                        'network_sent_mb', 'network_recv_mb'
                    ]
                    writer.writerow(headers)
                    print(f"📄 Created new combined file: {combined_csv}")
                
                # Write only the latest data point
                latest_data = self.data_log[-1]
                row = [
                    latest_data['timestamp'],
                    latest_data['cpu']['usage_percent'],
                    latest_data['memory']['usage_percent'],
                    latest_data['memory']['used_gb'],
                    latest_data['disk']['usage_percent'],
                    latest_data['disk']['free_gb'],
                    latest_data['system']['process_count'],
                    latest_data['system']['temperature_celsius'] or 0,
                    latest_data['network']['bytes_sent'] / (1024**2),
                    latest_data['network']['bytes_received'] / (1024**2)
                ]
                writer.writerow(row)
            
            # Save complete JSON (overwrite with all data)
            with open(combined_json, 'w') as f:
                json.dump(self.data_log, f, indent=2)
            
            print(f"💾 Updated combined files: {len(self.data_log)} total records")
            
        except Exception as e:
            print(f"❌ Error saving continuous data: {e}")
    
    def analyze_collected_data(self):
        """Simple analysis of collected data"""
        if not self.data_log:
            print("❌ No data to analyze")
            return
        
        print(f"\n📈 DATA ANALYSIS ({len(self.data_log)} data points):")
        print("=" * 50)
        
        # CPU Analysis
        cpu_values = [d['cpu']['usage_percent'] for d in self.data_log]
        print(f"🖥️  CPU Usage:")
        print(f"   Average: {sum(cpu_values)/len(cpu_values):.1f}%")
        print(f"   Min: {min(cpu_values):.1f}% | Max: {max(cpu_values):.1f}%")
        
        # Memory Analysis
        memory_values = [d['memory']['usage_percent'] for d in self.data_log]
        print(f"🧠 Memory Usage:")
        print(f"   Average: {sum(memory_values)/len(memory_values):.1f}%")
        print(f"   Min: {min(memory_values):.1f}% | Max: {max(memory_values):.1f}%")
        
        # Disk Analysis
        disk_values = [d['disk']['usage_percent'] for d in self.data_log]
        print(f"💾 Disk Usage:")
        print(f"   Average: {sum(disk_values)/len(disk_values):.1f}%")
        print(f"   Min: {min(disk_values):.1f}% | Max: {max(disk_values):.1f}%")
        
        # Temperature Analysis (if available)
        temp_values = [d['system']['temperature_celsius'] for d in self.data_log if d['system']['temperature_celsius']]
        if temp_values:
            print(f"🌡️  Temperature:")
            print(f"   Average: {sum(temp_values)/len(temp_values):.1f}°C")
            print(f"   Min: {min(temp_values):.1f}°C | Max: {max(temp_values):.1f}°C")
        
        print("=" * 50)

def main():
    """Main function to run system monitoring"""
    monitor = SimpleSystemMonitor()
    
    # Show basic system info
    monitor.get_basic_system_info()
    
    # Menu
    while True:
        print(f"\n🤖 What would you like to do? (Data saves to: {monitor.data_dir})")
        print("1. Check current status (one-time)")
        print("2. Collect data for training (continuous)")
        print("3. Analyze collected data")
        print("4. Save current session data to timestamped files")
        print("5. View data directory contents")
        print("6. Exit")
        
        choice = input("\nEnter choice (1-6): ").strip()
        
        if choice == '1':
            current_data = monitor.get_current_status()
            monitor.display_current_status(current_data)
        
        elif choice == '2':
            duration = input("Duration in minutes (default 5): ").strip()
            duration = int(duration) if duration.isdigit() else 5
            
            interval = input("Interval in seconds (default 30): ").strip()
            interval = int(interval) if interval.isdigit() else 30
            
            monitor.collect_data_continuously(duration, interval)
        
        elif choice == '3':
            monitor.analyze_collected_data()
        
        elif choice == '4':
            monitor.save_data_to_files()
        
        elif choice == '5':
            print(f"\n📁 Contents of {monitor.data_dir}:")
            try:
                files = os.listdir(monitor.data_dir)
                if files:
                    for file in sorted(files):
                        file_path = os.path.join(monitor.data_dir, file)
                        size = os.path.getsize(file_path)
                        modified = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                        print(f"   📄 {file} ({size:,} bytes, modified: {modified.strftime('%Y-%m-%d %H:%M:%S')})")
                else:
                    print("   📂 Directory is empty")
            except Exception as e:
                print(f"   ❌ Error reading directory: {e}")
        
        elif choice == '6':
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice, please try again")

if __name__ == "__main__":
    main()