use std::time::{Duration, Instant};
use std::process::Command;
use std::str::FromStr;
use windows::Win32::System::Power::GetSystemPowerStatus;
use windows::Win32::System::Power::SYSTEM_POWER_STATUS;

pub struct ThermalMonitor {
    last_temp: f32,
    last_check: Instant,
    spike_detected: bool,
    temperature_history: Vec<f32>,
    cpu_usage_history: Vec<f32>,
}

impl ThermalMonitor {
    pub fn new() -> Self {
        ThermalMonitor {
            last_temp: 0.0,
            last_check: Instant::now(),
            spike_detected: false,
            temperature_history: Vec::with_capacity(10),
            cpu_usage_history: Vec::with_capacity(10),
        }
    }

    // Get CPU usage using PowerShell
    fn get_cpu_usage(&self) -> Result<f32, String> {
        let output = Command::new("powershell")
            .args(&["-Command", "(Get-Counter '\\Processor(_Total)\\% Processor Time').CounterSamples.CookedValue"])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;

        let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();

        f32::from_str(&output_str)
            .map_err(|e| format!("Failed to parse CPU usage: {}", e))
    }

    // Get system temperature using battery and CPU usage as proxies
    fn get_system_temperature(&self) -> Result<f32, String> {
        // Try to get battery information first
        unsafe {
            let mut power_status = SYSTEM_POWER_STATUS::default();
            let result = GetSystemPowerStatus(&mut power_status);

            if result.as_bool() {
                // Battery temperature is not directly available, but we can use battery level as a proxy
                // since higher battery usage often correlates with higher temperatures
                let battery_life = power_status.BatteryLifePercent as f32;

                // If battery is discharging rapidly, it might indicate high system load
                if power_status.ACLineStatus == 0 && battery_life < 50.0 {
                    // Simulate higher temperature when battery is low and discharging
                    return Ok(45.0 + ((100.0 - battery_life) / 10.0));
                }
            }
        }

        // Fallback to CPU usage as a temperature proxy
        match self.get_cpu_usage() {
            Ok(cpu_usage) => {
                // Convert CPU usage to a temperature estimate
                // Higher CPU usage generally means higher temperature
                let estimated_temp = 40.0 + (cpu_usage / 5.0);
                Ok(estimated_temp)
            },
            Err(e) => {
                println!("Error getting CPU usage: {}. Using simulated data.", e);
                // If we can't get CPU usage, use a simulated value
                let current_temp = 45.0 + (rand::random::<f32>() * 5.0);
                Ok(current_temp)
            }
        }
    }

    pub fn check_temperature(&mut self) -> Result<f32, String> {
        // Try to get real temperature data
        let current_temp = match self.get_system_temperature() {
            Ok(temp) => temp,
            Err(e) => {
                println!("Error getting temperature: {}. Using simulated data.", e);
                45.0 + (rand::random::<f32>() * 5.0)
            }
        };

        // Also try to get CPU usage
        let cpu_usage = match self.get_cpu_usage() {
            Ok(usage) => usage,
            Err(_) => rand::random::<f32>() * 100.0, // Simulate CPU usage if we can't get real data
        };

        // Store in history
        self.temperature_history.push(current_temp);
        if self.temperature_history.len() > 10 {
            self.temperature_history.remove(0);
        }

        self.cpu_usage_history.push(cpu_usage);
        if self.cpu_usage_history.len() > 10 {
            self.cpu_usage_history.remove(0);
        }

        // Check for temperature spike
        if self.last_temp > 0.0 {
            let temp_diff = current_temp - self.last_temp;
            let time_diff = self.last_check.elapsed();

            // If temperature increased by more than 10°C in less than 10 seconds
            if temp_diff > 10.0 && time_diff < Duration::from_secs(10) {
                self.spike_detected = true;
                println!("Temperature spike detected! {:.1}°C → {:.1}°C", self.last_temp, current_temp);
            }
        }

        self.last_temp = current_temp;
        self.last_check = Instant::now();

        Ok(current_temp)
    }

    pub fn get_threat_score(&self) -> u8 {
        // If a spike was detected, that's an immediate high threat
        if self.spike_detected {
            return 80;
        }

        // Calculate score based on temperature history and CPU usage
        if !self.temperature_history.is_empty() && !self.cpu_usage_history.is_empty() {
            // Calculate average temperature
            let avg_temp: f32 = self.temperature_history.iter().sum::<f32>() / self.temperature_history.len() as f32;

            // Calculate average CPU usage
            let avg_cpu: f32 = self.cpu_usage_history.iter().sum::<f32>() / self.cpu_usage_history.len() as f32;

            // Calculate temperature variance (to detect unusual patterns)
            let temp_variance = if self.temperature_history.len() > 1 {
                let mean = avg_temp;
                let variance: f32 = self.temperature_history.iter()
                    .map(|&x| (x - mean).powi(2))
                    .sum::<f32>() / (self.temperature_history.len() - 1) as f32;
                variance
            } else {
                0.0
            };

            // Calculate threat score based on multiple factors
            // 1. High average temperature (above 60°C is concerning)
            // 2. High CPU usage (above 80% is concerning)
            // 3. High temperature variance (unusual fluctuations)

            let temp_score = if avg_temp > 60.0 {
                ((avg_temp - 60.0) * 2.0).min(40.0)
            } else {
                0.0
            };

            let cpu_score = if avg_cpu > 80.0 {
                ((avg_cpu - 80.0) * 2.0).min(40.0)
            } else {
                0.0
            };

            let variance_score = (temp_variance * 10.0).min(20.0);

            // Combine scores
            let total_score = temp_score + cpu_score + variance_score;

            return total_score as u8;
        }

        // Default to 0 if no data is available
        0
    }
}
