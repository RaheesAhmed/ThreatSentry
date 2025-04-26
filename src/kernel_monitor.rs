use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};
use std::thread;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub suspicious_score: u8,
}

#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    pub device_id: String,
    pub description: String,
    #[allow(dead_code)]
    pub insertion_time: Instant,
}

pub struct KernelMonitor {
    processes: Arc<Mutex<HashMap<u32, ProcessInfo>>>,
    usb_devices: Arc<Mutex<Vec<UsbDeviceInfo>>>,
    is_monitoring: Arc<Mutex<bool>>,
    suspicious_processes: Arc<Mutex<Vec<ProcessInfo>>>,
    new_usb_devices: Arc<Mutex<Vec<UsbDeviceInfo>>>,
}

impl KernelMonitor {
    pub fn new() -> Self {
        KernelMonitor {
            processes: Arc::new(Mutex::new(HashMap::new())),
            usb_devices: Arc::new(Mutex::new(Vec::new())),
            is_monitoring: Arc::new(Mutex::new(false)),
            suspicious_processes: Arc::new(Mutex::new(Vec::new())),
            new_usb_devices: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn start_monitoring(&self) -> Result<(), String> {
        println!("Starting kernel telemetry monitoring...");

        // Set monitoring flag
        let mut is_monitoring = self.is_monitoring.lock().unwrap();
        *is_monitoring = true;
        drop(is_monitoring);

        // Clone the shared state for the monitoring thread
        let processes = self.processes.clone();
        let usb_devices = self.usb_devices.clone();
        let is_monitoring_clone = self.is_monitoring.clone();
        let suspicious_processes = self.suspicious_processes.clone();
        let new_usb_devices = self.new_usb_devices.clone();

        // Start the monitoring thread
        thread::spawn(move || {
            let mut last_process_check = Instant::now();
            let mut last_usb_check = Instant::now();
            let mut known_usb_ids = Vec::new();

            while *is_monitoring_clone.lock().unwrap() {
                // Check processes every 2 seconds
                if last_process_check.elapsed() >= Duration::from_secs(2) {
                    if let Ok(current_processes) = Self::get_running_processes() {
                        // Update processes map
                        let mut processes_map = processes.lock().unwrap();
                        let mut suspicious = Vec::new();

                        for process in current_processes {
                            // Check if process is suspicious
                            if Self::is_process_suspicious(&process) {
                                suspicious.push(process.clone());
                            }
                            processes_map.insert(process.pid, process);
                        }

                        // Update suspicious processes
                        if !suspicious.is_empty() {
                            let mut suspicious_list = suspicious_processes.lock().unwrap();
                            *suspicious_list = suspicious;
                        }
                    }
                    last_process_check = Instant::now();
                }

                // Check USB devices every 5 seconds
                if last_usb_check.elapsed() >= Duration::from_secs(5) {
                    if let Ok(current_devices) = Self::get_usb_devices() {
                        // Check for new devices
                        let mut new_devices = Vec::new();
                        for device in &current_devices {
                            if !known_usb_ids.contains(&device.device_id) {
                                known_usb_ids.push(device.device_id.clone());
                                new_devices.push(device.clone());
                            }
                        }

                        // Update USB devices list
                        let mut usb_list = usb_devices.lock().unwrap();
                        *usb_list = current_devices;

                        // Update new USB devices
                        if !new_devices.is_empty() {
                            let mut new_list = new_usb_devices.lock().unwrap();
                            for device in new_devices {
                                new_list.push(device);
                            }
                        }
                    }
                    last_usb_check = Instant::now();
                }

                thread::sleep(Duration::from_millis(500));
            }
        });

        println!("Kernel telemetry monitoring started successfully");
        Ok(())
    }

    pub fn stop_monitoring(&self) {
        let mut is_monitoring = self.is_monitoring.lock().unwrap();
        *is_monitoring = false;
    }

    pub fn get_suspicious_processes(&self) -> Vec<ProcessInfo> {
        self.suspicious_processes.lock().unwrap().clone()
    }

    pub fn get_new_usb_devices(&self) -> Vec<UsbDeviceInfo> {
        self.new_usb_devices.lock().unwrap().clone()
    }

    pub fn get_threat_score(&self) -> u8 {
        let suspicious_processes = self.suspicious_processes.lock().unwrap();
        let new_usb_devices = self.new_usb_devices.lock().unwrap();

        // Calculate threat score based on suspicious processes and new USB devices
        let process_score = if suspicious_processes.is_empty() {
            0
        } else {
            let max_score = suspicious_processes.iter()
                .map(|p| p.suspicious_score)
                .max()
                .unwrap_or(0);

            // Weight by number of suspicious processes
            let count_factor = (suspicious_processes.len() as f32).min(5.0) / 5.0;
            ((max_score as f32) * (0.7 + 0.3 * count_factor)) as u8
        };

        // USB devices contribute to the score
        let usb_score = if new_usb_devices.is_empty() {
            0
        } else {
            // Each new USB device adds to the score
            let base_score = 30; // Base score for any USB insertion
            let count_factor = (new_usb_devices.len() as f32).min(3.0) / 3.0;
            (base_score as f32 * (1.0 + count_factor)) as u8
        };

        // Combine scores, capping at 100
        let combined = process_score.max(usb_score);
        combined.min(100)
    }

    // Helper function to get running processes
    fn get_running_processes() -> Result<Vec<ProcessInfo>, String> {
        let output = Command::new("powershell")
            .args(&["-Command", "Get-Process | Select-Object Name, Id, CPU, WorkingSet | ConvertTo-Csv -NoTypeInformation"])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = output_str.lines().collect();

        let mut processes = Vec::new();

        // Skip header line
        for line in lines.iter().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 4 {
                // Remove quotes from CSV format
                let name = parts[0].trim_matches('"').to_string();
                let pid = parts[1].trim_matches('"').parse::<u32>().unwrap_or(0);
                let cpu = parts[2].trim_matches('"').parse::<f32>().unwrap_or(0.0);
                let memory = parts[3].trim_matches('"').parse::<f32>().unwrap_or(0.0);

                // Calculate suspicious score
                let suspicious_score = Self::calculate_process_score(&name, cpu, memory);

                processes.push(ProcessInfo {
                    name,
                    pid,
                    cpu_usage: cpu,
                    memory_usage: memory,
                    suspicious_score,
                });
            }
        }

        Ok(processes)
    }

    // Helper function to get USB devices
    fn get_usb_devices() -> Result<Vec<UsbDeviceInfo>, String> {
        let output = Command::new("powershell")
            .args(&["-Command", "Get-PnpDevice -Class USB | Select-Object InstanceId, FriendlyName | ConvertTo-Csv -NoTypeInformation"])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = output_str.lines().collect();

        let mut devices = Vec::new();

        // Skip header line
        for line in lines.iter().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                // Remove quotes from CSV format
                let device_id = parts[0].trim_matches('"').to_string();
                let description = parts[1].trim_matches('"').to_string();

                devices.push(UsbDeviceInfo {
                    device_id,
                    description,
                    insertion_time: Instant::now(),
                });
            }
        }

        Ok(devices)
    }

    // Helper function to check if a process is suspicious
    fn is_process_suspicious(process: &ProcessInfo) -> bool {
        // Check for high CPU usage
        if process.cpu_usage > 70.0 {
            return true;
        }

        // Check for high memory usage (> 500MB)
        if process.memory_usage > 500_000_000.0 {
            return true;
        }

        // Check for suspicious process names
        let suspicious_names = [
            "miner", "xmrig", "cryptonight", "monero",
            "ethminer", "cgminer", "bfgminer", "nicehash",
            "backdoor", "trojan", "keylogger", "spyware",
            "malware", "virus", "rootkit", "exploit",
        ];

        for name in suspicious_names.iter() {
            if process.name.to_lowercase().contains(name) {
                return true;
            }
        }

        false
    }

    // Helper function to calculate process suspicious score
    fn calculate_process_score(name: &str, cpu: f32, memory: f32) -> u8 {
        let mut score = 0;

        // CPU usage contributes to score
        if cpu > 90.0 {
            score += 40;
        } else if cpu > 70.0 {
            score += 30;
        } else if cpu > 50.0 {
            score += 20;
        }

        // Memory usage contributes to score (in MB)
        let memory_mb = memory / 1_000_000.0;
        if memory_mb > 1000.0 {
            score += 30;
        } else if memory_mb > 500.0 {
            score += 20;
        } else if memory_mb > 200.0 {
            score += 10;
        }

        // Check for suspicious process names
        let suspicious_names = [
            ("miner", 50), ("xmrig", 70), ("cryptonight", 60), ("monero", 50),
            ("ethminer", 60), ("cgminer", 60), ("bfgminer", 60), ("nicehash", 50),
            ("backdoor", 80), ("trojan", 90), ("keylogger", 90), ("spyware", 80),
            ("malware", 90), ("virus", 90), ("rootkit", 90), ("exploit", 70),
        ];

        for (suspicious_name, name_score) in suspicious_names.iter() {
            if name.to_lowercase().contains(suspicious_name) {
                score = score.max(*name_score);
            }
        }

        // Cap at 100
        score.min(100)
    }
}
