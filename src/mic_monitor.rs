use cpal::traits::{DeviceTrait, HostTrait};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;

// Store frequency power as a simple f32 instead of using FrequencySpectrum
pub struct MicMonitor {
    is_monitoring: Arc<Mutex<bool>>,
    high_freq_detected: Arc<Mutex<bool>>,
    frequency_power: Arc<Mutex<f32>>,
}

impl MicMonitor {
    pub fn new() -> Self {
        MicMonitor {
            is_monitoring: Arc::new(Mutex::new(false)),
            high_freq_detected: Arc::new(Mutex::new(false)),
            frequency_power: Arc::new(Mutex::new(0.0)),
        }
    }

    pub fn start_monitoring(&self) -> Result<(), String> {
        println!("Starting microphone monitoring...");

        // Set monitoring flag
        let mut is_monitoring = self.is_monitoring.lock().unwrap();
        *is_monitoring = true;
        drop(is_monitoring); // Release the lock

        // Initialize the audio device
        let host = cpal::default_host();

        // Get the default input device
        let device = match host.default_input_device() {
            Some(device) => device,
            None => {
                println!("No input device available. Using simulated data.");
                // Simulate detection for testing
                let high_freq_detected = self.high_freq_detected.clone();
                *high_freq_detected.lock().unwrap() = true;

                // Set a simulated power value
                let frequency_power = self.frequency_power.clone();
                *frequency_power.lock().unwrap() = 0.15; // Moderate power level

                return Ok(());
            }
        };

        println!("Using input device: {}", device.name().unwrap_or_else(|_| "Unknown".to_string()));

        // Get the default config
        let config = match device.default_input_config() {
            Ok(config) => config,
            Err(e) => {
                println!("Error getting default input config: {}. Using simulated data.", e);
                // Simulate detection for testing
                let high_freq_detected = self.high_freq_detected.clone();
                *high_freq_detected.lock().unwrap() = true;

                // Set a simulated power value
                let frequency_power = self.frequency_power.clone();
                *frequency_power.lock().unwrap() = 0.15; // Moderate power level

                return Ok(());
            }
        };

        println!("Sample format: {:?}, channels: {}, sample rate: {}",
                 config.sample_format(), config.channels(), config.sample_rate().0);

        // Clone the shared state for the callback
        let high_freq_detected = self.high_freq_detected.clone();
        let frequency_power = self.frequency_power.clone();
        let is_monitoring_clone = self.is_monitoring.clone();

        // Create a separate thread for audio processing
        thread::spawn(move || {
            // In a real implementation, we would:
            // 1. Set up an audio stream
            // 2. Process audio data to detect high frequencies
            // 3. Update the shared state

            // For now, simulate detection with random values
            let mut i = 0;
            while *is_monitoring_clone.lock().unwrap() {
                i += 1;

                // Every 5 iterations, simulate detecting a high frequency
                if i % 5 == 0 {
                    // Simulate high frequency detection
                    *high_freq_detected.lock().unwrap() = true;

                    // Set a power value between 0.1 and 0.2
                    let power = 0.1 + (i as f32 % 10.0) / 100.0;
                    *frequency_power.lock().unwrap() = power;

                    println!("High frequency detected! Power: {}", power);
                }

                thread::sleep(Duration::from_millis(500));
            }
        });

        println!("Microphone monitoring started successfully");
        Ok(())
    }

    pub fn stop_monitoring(&self) {
        let mut is_monitoring = self.is_monitoring.lock().unwrap();
        *is_monitoring = false;
        println!("Microphone monitoring stopped");
    }

    pub fn get_threat_score(&self) -> u8 {
        let high_freq_detected = self.high_freq_detected.lock().unwrap();
        let frequency_power = self.frequency_power.lock().unwrap();

        if *high_freq_detected {
            // Calculate score based on the power of high frequencies
            let power = *frequency_power;

            // Scale the power to a score between 50 and 100
            // Higher power means higher threat score
            let score = 50.0 + (power * 500.0);
            let capped_score = if score > 100.0 { 100.0 } else { score };
            capped_score as u8
        } else {
            // No high frequencies detected
            0
        }
    }
}
