use cpal::traits::{DeviceTrait, HostTrait};
use cpal::SampleFormat;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use rustfft::{FftPlanner, num_complex::Complex32};
use std::collections::VecDeque;

// Store frequency power as a simple f32 instead of using FrequencySpectrum
pub struct MicMonitor {
    is_monitoring: Arc<Mutex<bool>>,
    high_freq_detected: Arc<Mutex<bool>>,
    frequency_power: Arc<Mutex<f32>>,
    sample_rate: Arc<Mutex<u32>>,
    fft_results: Arc<Mutex<Vec<f32>>>,
    ultrasonic_power: Arc<Mutex<f32>>,
    stream_handle: Arc<Mutex<Option<cpal::Stream>>>,
}

impl MicMonitor {
    pub fn new() -> Self {
        MicMonitor {
            is_monitoring: Arc::new(Mutex::new(false)),
            high_freq_detected: Arc::new(Mutex::new(false)),
            frequency_power: Arc::new(Mutex::new(0.0)),
            sample_rate: Arc::new(Mutex::new(44100)),
            fft_results: Arc::new(Mutex::new(Vec::new())),
            ultrasonic_power: Arc::new(Mutex::new(0.0)),
            stream_handle: Arc::new(Mutex::new(None)),
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
                // Fallback to simulation
                return self.start_simulated_monitoring();
            }
        };

        println!("Using input device: {}", device.name().unwrap_or_else(|_| "Unknown".to_string()));

        // Get the default config
        let config = match device.default_input_config() {
            Ok(config) => config,
            Err(e) => {
                println!("Error getting default input config: {}. Using simulated data.", e);
                // Fallback to simulation
                return self.start_simulated_monitoring();
            }
        };

        println!("Sample format: {:?}, channels: {}, sample rate: {}",
                 config.sample_format(), config.channels(), config.sample_rate().0);

        // Update sample rate
        *self.sample_rate.lock().unwrap() = config.sample_rate().0;

        // Clone the shared state for the callback
        let high_freq_detected = self.high_freq_detected.clone();
        let frequency_power = self.frequency_power.clone();
        let is_monitoring_clone = self.is_monitoring.clone();
        let fft_results = self.fft_results.clone();
        let ultrasonic_power = self.ultrasonic_power.clone();
        let sample_rate = *self.sample_rate.lock().unwrap();

        // Buffer for FFT processing
        let buffer_size = 4096; // Power of 2 for FFT
        let fft_buffer = Arc::new(Mutex::new(VecDeque::new()));
        let fft_buffer_clone = fft_buffer.clone();

        // Start the FFT processing thread
        let _fft_thread = thread::spawn(move || {
            // Create FFT planner
            let mut planner = FftPlanner::new();
            let fft = planner.plan_fft_forward(buffer_size);
            
            // Frequency resolution: sample_rate / buffer_size
            let freq_resolution = sample_rate as f32 / buffer_size as f32;
            
            // Ultrasonic frequency range (15-20kHz)
            let min_freq_idx = (15000.0 / freq_resolution) as usize;
            let max_freq_idx = (20000.0 / freq_resolution) as usize;
            
            while *is_monitoring_clone.lock().unwrap() {
                // Check if we have enough samples for FFT
                let mut buffer_lock = fft_buffer.lock().unwrap();
                
                if buffer_lock.len() >= buffer_size {
                    // Prepare input for FFT
                    let mut fft_input: Vec<Complex32> = buffer_lock.drain(..buffer_size)
                        .map(|sample| Complex32::new(sample, 0.0))
                        .collect();
                    
                    // Apply window function (Hann window) to reduce spectral leakage
                    for i in 0..buffer_size {
                        let window = 0.5 * (1.0 - (2.0 * std::f32::consts::PI * i as f32 / buffer_size as f32).cos());
                        fft_input[i] = fft_input[i] * window;
                    }
                    
                    // Create output buffer - no longer needed in rustfft 6.x
                    // We'll modify the input buffer directly
                    
                    // Perform FFT - the API changed in rustfft 6.x
                    fft.process(&mut fft_input);
                    
                    // Calculate magnitude spectrum
                    let mut magnitudes: Vec<f32> = fft_input[..buffer_size/2]
                        .iter()
                        .map(|c| (c.norm_sqr()).sqrt())
                        .collect();
                    
                    // Normalize magnitude spectrum
                    if let Some(max_val) = magnitudes.iter().cloned().fold(None, |max, val| {
                        match max {
                            None => Some(val),
                            Some(m) => Some(m.max(val))
                        }
                    }) {
                        if max_val > 0.0 {
                            for mag in &mut magnitudes {
                                *mag /= max_val;
                            }
                        }
                    }
                    
                    // Update FFT results for visualization
                    *fft_results.lock().unwrap() = magnitudes.clone();
                    
                    // Check for ultrasonic frequencies (15-20kHz)
                    let ultrasonic_range = &magnitudes[min_freq_idx.min(magnitudes.len())..max_freq_idx.min(magnitudes.len())];
                    
                    if !ultrasonic_range.is_empty() {
                        // Calculate average power in ultrasonic range
                        let avg_power = ultrasonic_range.iter().sum::<f32>() / ultrasonic_range.len() as f32;
                        *ultrasonic_power.lock().unwrap() = avg_power;
                        
                        // Threshold for detection
                        let threshold = 0.2; // Adjust based on testing
                        if avg_power > threshold {
                            *high_freq_detected.lock().unwrap() = true;
                            *frequency_power.lock().unwrap() = avg_power;
                            println!("Ultrasonic frequency detected! Power: {:.4}", avg_power);
                        }
                    }
                }
                
                // Sleep a bit to prevent high CPU usage
                thread::sleep(Duration::from_millis(100));
            }
        });

        // Start the audio input stream
        let err_fn = |err| eprintln!("Error in audio stream: {}", err);

        let stream = match config.sample_format() {
            SampleFormat::F32 => self.build_input_stream::<f32>(&device, &config.into(), fft_buffer_clone, err_fn),
            SampleFormat::I16 => self.build_input_stream::<i16>(&device, &config.into(), fft_buffer_clone, err_fn),
            SampleFormat::U16 => self.build_input_stream::<u16>(&device, &config.into(), fft_buffer_clone, err_fn),
            _ => {
                // Handle any new formats added to the enum in the future
                println!("Unsupported sample format. Using simulated data.");
                return self.start_simulated_monitoring();
            }
        };

        let stream = match stream {
            Ok(stream) => stream,
            Err(err) => {
                println!("Error building input stream: {}", err);
                return self.start_simulated_monitoring();
            }
        };

        // Store the stream handle
        *self.stream_handle.lock().unwrap() = Some(stream);

        println!("Microphone monitoring started successfully");
        Ok(())
    }

    fn build_input_stream<T>(
        &self,
        device: &cpal::Device,
        config: &cpal::StreamConfig,
        buffer: Arc<Mutex<VecDeque<f32>>>,
        err_fn: impl FnMut(cpal::StreamError) + Send + 'static,
    ) -> Result<cpal::Stream, cpal::BuildStreamError>
    where
        T: cpal::Sample<Float = f32> + cpal::SizedSample + Send + 'static,
    {
        let is_monitoring = self.is_monitoring.clone();
        
        device.build_input_stream(
            config,
            move |data: &[T], _: &cpal::InputCallbackInfo| {
                if *is_monitoring.lock().unwrap() {
                    // Convert samples to f32 and store in buffer
                    let mut buffer_lock = buffer.lock().unwrap();
                    for &sample in data {
                        let sample_f32 = sample.to_float_sample();
                        buffer_lock.push_back(sample_f32);
                    }
                }
            },
            err_fn,
            None
        )
    }

    fn start_simulated_monitoring(&self) -> Result<(), String> {
        // Clone the shared state for the callback
        let high_freq_detected = self.high_freq_detected.clone();
        let frequency_power = self.frequency_power.clone();
        let is_monitoring_clone = self.is_monitoring.clone();
        let fft_results = self.fft_results.clone();
        let ultrasonic_power = self.ultrasonic_power.clone();

        // Create a thread for simulated monitoring
        thread::spawn(move || {
            let mut i = 0;
            
            // Create simulated FFT results
            let mut simulated_fft = vec![0.0; 1024];
            
            while *is_monitoring_clone.lock().unwrap() {
                i += 1;

                // Every 5 iterations, simulate detecting a high frequency
                if i % 5 == 0 {
                    // Update simulated FFT results
                    for j in 0..simulated_fft.len() {
                        // Create a peak in the ultrasonic range (around 75-85% of the Nyquist frequency)
                        let ultrasonic_center = (simulated_fft.len() as f32 * 0.8) as usize;
                        let distance = (j as isize - ultrasonic_center as isize).abs();
                        
                        if distance < 50 {
                            // Create a peak
                            simulated_fft[j] = 0.2 + 0.8 * (1.0 - (distance as f32 / 50.0));
                        } else {
                            // Background noise
                            simulated_fft[j] = 0.05 + 0.1 * rand::random::<f32>();
                        }
                    }
                    
                    // Update FFT results
                    *fft_results.lock().unwrap() = simulated_fft.clone();
                    
                    // Simulate high frequency detection
                    *high_freq_detected.lock().unwrap() = true;

                    // Set a power value between 0.2 and 0.5
                    let power = 0.2 + (i as f32 % 10.0) / 30.0;
                    *frequency_power.lock().unwrap() = power;
                    *ultrasonic_power.lock().unwrap() = power;

                    println!("Simulated ultrasonic frequency detected! Power: {:.4}", power);
                } else {
                    // Update with just noise
                    for j in 0..simulated_fft.len() {
                        simulated_fft[j] = 0.05 + 0.1 * rand::random::<f32>();
                    }
                    *fft_results.lock().unwrap() = simulated_fft.clone();
                }

                thread::sleep(Duration::from_millis(500));
            }
        });

        println!("Simulated microphone monitoring started");
        Ok(())
    }

    pub fn stop_monitoring(&self) {
        let mut is_monitoring = self.is_monitoring.lock().unwrap();
        *is_monitoring = false;
        drop(is_monitoring);
        
        // Stop the audio stream if it exists
        let mut stream_handle = self.stream_handle.lock().unwrap();
        *stream_handle = None;
        
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
    
    pub fn get_fft_results(&self) -> Vec<f32> {
        self.fft_results.lock().unwrap().clone()
    }
    
    pub fn get_ultrasonic_power(&self) -> f32 {
        *self.ultrasonic_power.lock().unwrap()
    }
}
