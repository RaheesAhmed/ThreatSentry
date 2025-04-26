use eframe::{egui, App};
use egui_plot::{Line, Plot, PlotPoints, Legend, Corner};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::thread;
use std::collections::HashMap;
use egui::Color32;

use crate::email_monitor::EmailMonitor;
use crate::mic_monitor::MicMonitor;
use crate::thermal_monitor::ThermalMonitor;
use crate::kernel_monitor::KernelMonitor;

// 3D point structure for visualization
#[derive(Clone)]
struct Point3D {
    x: f32,
    y: f32,
    z: f32,
    color: Color32,
    size: f32,
}

// Threat origin data
#[derive(Clone)]
struct ThreatOrigin {
    country: String,
    latitude: f32,
    longitude: f32,
    threat_count: i32,
    threat_type: String,
}

// Added fields for 3D visualization and threat map
pub struct MonitoringData {
    pub mic_score: Arc<Mutex<u8>>,
    pub thermal_score: Arc<Mutex<u8>>,
    pub kernel_score: Arc<Mutex<u8>>,
    pub email_score: Arc<Mutex<u8>>,
    pub combined_score: Arc<Mutex<u8>>,
    pub temperature_history: Arc<Mutex<Vec<f32>>>,
    pub mic_power_history: Arc<Mutex<Vec<f32>>>,
    pub time_history: Arc<Mutex<Vec<f64>>>,
    pub urls: Arc<Mutex<Vec<(String, u8)>>>,
    pub suspicious_processes: Arc<Mutex<Vec<String>>>,
    pub new_usb_devices: Arc<Mutex<Vec<String>>>,
    pub is_monitoring: Arc<Mutex<bool>>,
    pub fft_data: Arc<Mutex<Vec<f32>>>,  // Added for FFT visualization
    pub system_activity_3d: Arc<Mutex<Vec<Point3D>>>, // 3D system activity
    pub threat_origins: Arc<Mutex<Vec<ThreatOrigin>>>, // Threat origins for map
    pub selected_threat: Arc<Mutex<Option<String>>>, // For drill-down
    pub threat_details: Arc<Mutex<HashMap<String, String>>>, // Details for drill-down
}

impl MonitoringData {
    pub fn new() -> Self {
        MonitoringData {
            mic_score: Arc::new(Mutex::new(0)),
            thermal_score: Arc::new(Mutex::new(0)),
            kernel_score: Arc::new(Mutex::new(0)),
            email_score: Arc::new(Mutex::new(0)),
            combined_score: Arc::new(Mutex::new(0)),
            temperature_history: Arc::new(Mutex::new(Vec::new())),
            mic_power_history: Arc::new(Mutex::new(Vec::new())),
            time_history: Arc::new(Mutex::new(Vec::new())),
            urls: Arc::new(Mutex::new(Vec::new())),
            suspicious_processes: Arc::new(Mutex::new(Vec::new())),
            new_usb_devices: Arc::new(Mutex::new(Vec::new())),
            is_monitoring: Arc::new(Mutex::new(false)),
            fft_data: Arc::new(Mutex::new(Vec::new())),
            system_activity_3d: Arc::new(Mutex::new(Vec::new())),
            threat_origins: Arc::new(Mutex::new(Vec::new())),
            selected_threat: Arc::new(Mutex::new(None)),
            threat_details: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub struct ThreatSentryApp {
    monitoring_data: MonitoringData,
    start_time: Instant,
    username: String,
    password: String,
    visualization_tab: usize, // 0 = Classic, 1 = 3D, 2 = Map
    show_fft: bool,
    show_drill_down: bool,
    rotation_angle: f32,
}

impl ThreatSentryApp {
    pub fn new(username: String, password: String) -> Self {
        ThreatSentryApp {
            monitoring_data: MonitoringData::new(),
            start_time: Instant::now(),
            username,
            password,
            visualization_tab: 0,
            show_fft: false,
            show_drill_down: false,
            rotation_angle: 0.0,
        }
    }

    pub fn start_monitoring(&self) {
        let mut is_monitoring = self.monitoring_data.is_monitoring.lock().unwrap();
        if *is_monitoring {
            return; // Already monitoring
        }
        *is_monitoring = true;
        drop(is_monitoring);

        // Clone the shared data for the monitoring thread
        let mic_score = self.monitoring_data.mic_score.clone();
        let thermal_score = self.monitoring_data.thermal_score.clone();
        let kernel_score = self.monitoring_data.kernel_score.clone();
        let email_score = self.monitoring_data.email_score.clone();
        let combined_score = self.monitoring_data.combined_score.clone();
        let temperature_history = self.monitoring_data.temperature_history.clone();
        let mic_power_history = self.monitoring_data.mic_power_history.clone();
        let time_history = self.monitoring_data.time_history.clone();
        let urls = self.monitoring_data.urls.clone();
        let suspicious_processes = self.monitoring_data.suspicious_processes.clone();
        let new_usb_devices = self.monitoring_data.new_usb_devices.clone();
        let is_monitoring_clone = self.monitoring_data.is_monitoring.clone();
        let username = self.username.clone();
        let password = self.password.clone();
        let fft_data = self.monitoring_data.fft_data.clone(); // Added for FFT data

        // Start the monitoring thread
        thread::spawn(move || {
            // Initialize monitors
            let mic_monitor = MicMonitor::new();
            let mut thermal_monitor = ThermalMonitor::new();
            let kernel_monitor = KernelMonitor::new();
            let email_monitor = EmailMonitor::new(
                username,
                password,
                "imap.gmail.com".to_string(),
            );

            // Start microphone monitoring
            match mic_monitor.start_monitoring() {
                Ok(_) => println!("Microphone monitoring started"),
                Err(e) => println!("Error starting microphone monitoring: {}", e),
            }

            // Start kernel monitoring
            match kernel_monitor.start_monitoring() {
                Ok(_) => println!("Kernel monitoring started"),
                Err(e) => println!("Error starting kernel monitoring: {}", e),
            }

            // Monitoring loop
            let start_time = Instant::now();
            let mut last_email_check = Instant::now() - Duration::from_secs(60); // Check emails immediately

            while *is_monitoring_clone.lock().unwrap() {
                // Check temperature
                if let Ok(temp) = thermal_monitor.check_temperature() {
                    let mut temp_history = temperature_history.lock().unwrap();
                    temp_history.push(temp);
                    if temp_history.len() > 100 {
                        temp_history.remove(0);
                    }
                }

                // Get thermal score
                let thermal_score_val = thermal_monitor.get_threat_score();
                *thermal_score.lock().unwrap() = thermal_score_val;

                // Get microphone score and FFT data
                let mic_score_val = mic_monitor.get_threat_score();
                *mic_score.lock().unwrap() = mic_score_val;
                
                // Get FFT data for visualization
                let fft_results = mic_monitor.get_fft_results();
                if !fft_results.is_empty() {
                    *fft_data.lock().unwrap() = fft_results;
                }

                // Get kernel score and update suspicious processes and USB devices
                let kernel_score_val = kernel_monitor.get_threat_score();
                *kernel_score.lock().unwrap() = kernel_score_val;

                // Update suspicious processes
                let suspicious = kernel_monitor.get_suspicious_processes();
                if !suspicious.is_empty() {
                    let mut processes = suspicious_processes.lock().unwrap();
                    processes.clear();
                    for process in suspicious {
                        processes.push(format!("{} (PID: {}, CPU: {:.1}%, Score: {})",
                            process.name, process.pid, process.cpu_usage, process.suspicious_score));
                    }
                }

                // Update USB devices
                let usb_devices = kernel_monitor.get_new_usb_devices();
                if !usb_devices.is_empty() {
                    let mut devices = new_usb_devices.lock().unwrap();
                    devices.clear();
                    for device in usb_devices {
                        devices.push(format!("{} (ID: {})", device.description, device.device_id));
                    }
                }

                // Add microphone power 
                let power = if mic_score_val > 0 {
                    // Get real ultrasonic power if available
                    let ultrasonic_power = mic_monitor.get_ultrasonic_power();
                    if ultrasonic_power > 0.0 {
                        ultrasonic_power
                    } else {
                        (mic_score_val as f32) / 200.0 + 0.05
                    }
                } else {
                    0.0
                };

                let mut mic_history = mic_power_history.lock().unwrap();
                mic_history.push(power);
                if mic_history.len() > 100 {
                    mic_history.remove(0);
                }

                // Add time point
                let elapsed = start_time.elapsed().as_secs_f64();
                let mut time_points = time_history.lock().unwrap();
                time_points.push(elapsed);
                if time_points.len() > 100 {
                    time_points.remove(0);
                }

                // Calculate combined threat score
                let mut scores = Vec::new();
                scores.push(mic_score_val);
                scores.push(thermal_score_val);
                scores.push(kernel_score_val);
                
                let combined = if !scores.is_empty() {
                    let sum: u32 = scores.iter().map(|&s| s as u32).sum();
                    (sum / scores.len() as u32) as u8
                } else {
                    0
                };
                
                *combined_score.lock().unwrap() = combined;

                // Check emails every 60 seconds
                if last_email_check.elapsed() > Duration::from_secs(60) {
                    last_email_check = Instant::now();

                    match email_monitor.fetch_emails(5) {
                        Ok(emails) => {
                            let extracted_urls = email_monitor.extract_urls(emails);
                            let scored_urls = email_monitor.scan_urls(extracted_urls);

                            // Update URLs
                            *urls.lock().unwrap() = scored_urls.clone();

                            // Update email score
                            let max_score = scored_urls.iter()
                                .map(|(_, score)| *score)
                                .max()
                                .unwrap_or(0);

                            *email_score.lock().unwrap() = max_score;
                            
                            // Recalculate combined score with email
                            scores.push(max_score);
                            let combined = if !scores.is_empty() {
                                let sum: u32 = scores.iter().map(|&s| s as u32).sum();
                                (sum / scores.len() as u32) as u8
                            } else {
                                0
                            };
                            *combined_score.lock().unwrap() = combined;
                        },
                        Err(e) => println!("Error fetching emails: {}", e),
                    }
                }

                thread::sleep(Duration::from_millis(100));
            }

            // Stop monitoring
            mic_monitor.stop_monitoring();
            kernel_monitor.stop_monitoring();
        });
    }

    pub fn stop_monitoring(&self) {
        let mut is_monitoring = self.monitoring_data.is_monitoring.lock().unwrap();
        *is_monitoring = false;
    }

    fn rotate_point(point: &mut Point3D, angle_x: f32, angle_y: f32) {
        // Rotate around Y axis
        let x = point.x;
        let z = point.z;
        point.x = x * angle_y.cos() - z * angle_y.sin();
        point.z = x * angle_y.sin() + z * angle_y.cos();

        // Rotate around X axis
        let y = point.y;
        let z = point.z;
        point.y = y * angle_x.cos() - z * angle_x.sin();
        point.z = y * angle_x.sin() + z * angle_x.cos();
    }

    fn draw_3d_point(ui: &mut egui::Ui, center_x: f32, center_y: f32, point: &Point3D, scale: f32) {
        let projected_x = center_x + point.x * scale;
        let projected_y = center_y + point.y * scale;
        let size = ((point.z + 10.0) / 20.0) * point.size;
        
        ui.painter().circle_filled(
            egui::pos2(projected_x, projected_y),
            size.max(1.0),
            point.color,
        );
    }

    fn update_3d_system_activity(&mut self) {
        let mut system_activity = self.monitoring_data.system_activity_3d.lock().unwrap();
        
        // Generate new points if needed
        if system_activity.len() < 100 {
            let mic_score = *self.monitoring_data.mic_score.lock().unwrap() as f32;
            let thermal_score = *self.monitoring_data.thermal_score.lock().unwrap() as f32;
            let kernel_score = *self.monitoring_data.kernel_score.lock().unwrap() as f32;
            
            // Add points representing different subsystems
            // Microphone activity (red points)
            if mic_score > 0.0 {
                for _ in 0..5 {
                    let distance = 5.0 + (mic_score / 10.0);
                    let angle = rand::random::<f32>() * std::f32::consts::PI * 2.0;
                    system_activity.push(Point3D {
                        x: angle.cos() * distance,
                        y: angle.sin() * distance,
                        z: rand::random::<f32>() * 5.0,
                        color: Color32::from_rgb(255, 50, 50),
                        size: 3.0 + (mic_score / 20.0),
                    });
                }
            }
            
            // Thermal activity (orange points)
            if thermal_score > 0.0 {
                for _ in 0..5 {
                    let distance = 3.0 + (thermal_score / 15.0);
                    let angle = rand::random::<f32>() * std::f32::consts::PI * 2.0;
                    system_activity.push(Point3D {
                        x: angle.cos() * distance,
                        y: angle.sin() * distance,
                        z: -rand::random::<f32>() * 5.0,
                        color: Color32::from_rgb(255, 165, 0),
                        size: 3.0 + (thermal_score / 20.0),
                    });
                }
            }
            
            // Kernel activity (blue points)
            if kernel_score > 0.0 {
                for _ in 0..5 {
                    let distance = 4.0 + (kernel_score / 12.0);
                    let angle = rand::random::<f32>() * std::f32::consts::PI * 2.0;
                    system_activity.push(Point3D {
                        x: angle.cos() * distance,
                        y: -5.0 + rand::random::<f32>() * 3.0,
                        z: angle.sin() * distance,
                        color: Color32::from_rgb(50, 100, 255),
                        size: 3.0 + (kernel_score / 20.0),
                    });
                }
            }
        }
        
        // Remove oldest points if too many
        if system_activity.len() > 300 {
            system_activity.drain(0..100);
        }
        
        // Rotate each point slightly for animation
        for point in system_activity.iter_mut() {
            Self::rotate_point(point, 0.01, 0.02);
        }
    }
    
    fn generate_threat_map_data(&mut self) {
        let mut threat_origins = self.monitoring_data.threat_origins.lock().unwrap();
        
        // Only regenerate occasionally
        if !threat_origins.is_empty() && rand::random::<f32>() < 0.95 {
            return;
        }
        
        // Clear existing data
        threat_origins.clear();
        
        // Get current threat scores
        let mic_score = *self.monitoring_data.mic_score.lock().unwrap();
        let thermal_score = *self.monitoring_data.thermal_score.lock().unwrap();
        let kernel_score = *self.monitoring_data.kernel_score.lock().unwrap();
        let email_score = *self.monitoring_data.email_score.lock().unwrap();
        
        // Add some example threat origins based on current scores
        if email_score > 30 {
            threat_origins.push(ThreatOrigin {
                country: "Russia".to_string(),
                latitude: 55.751244,
                longitude: 37.618423,
                threat_count: (email_score as i32 / 10).max(1),
                threat_type: "Phishing".to_string(),
            });
            
            threat_origins.push(ThreatOrigin {
                country: "Nigeria".to_string(),
                latitude: 9.0820,
                longitude: 8.6753,
                threat_count: (email_score as i32 / 15).max(1),
                threat_type: "Phishing".to_string(),
            });
        }
        
        if mic_score > 50 {
            threat_origins.push(ThreatOrigin {
                country: "Local Network".to_string(),
                latitude: 40.7128,
                longitude: -74.0060,
                threat_count: (mic_score as i32 / 20).max(1),
                threat_type: "Ultrasonic Beacon".to_string(),
            });
        }
        
        if thermal_score > 40 {
            threat_origins.push(ThreatOrigin {
                country: "China".to_string(),
                latitude: 39.9042,
                longitude: 116.4074,
                threat_count: (thermal_score as i32 / 10).max(1),
                threat_type: "Cryptominer".to_string(),
            });
        }
        
        if kernel_score > 45 {
            threat_origins.push(ThreatOrigin {
                country: "Iran".to_string(), 
                latitude: 35.6892,
                longitude: 51.3890,
                threat_count: (kernel_score as i32 / 15).max(1),
                threat_type: "System Exploit".to_string(),
            });
        }
        
        // Add threat details for drill-down
        let mut threat_details = self.monitoring_data.threat_details.lock().unwrap();
        threat_details.clear();
        
        for origin in threat_origins.iter() {
            let detail_key = format!("{}: {}", origin.country, origin.threat_type);
            let detail_value = match origin.threat_type.as_str() {
                "Phishing" => format!(
                    "Origin: {}\nType: Phishing Campaign\nCount: {} attempts\nTarget: Credentials\nSeverity: {}/10\nMitigation: Email filtering, 2FA", 
                    origin.country, 
                    origin.threat_count,
                    (email_score as f32 / 10.0).round()
                ),
                "Ultrasonic Beacon" => format!(
                    "Origin: Local Network\nType: Ultrasonic Data Exfiltration\nFrequency: 18-19 kHz\nPower: High\nSeverity: {}/10\nMitigation: Isolate network, disable microphone",
                    (mic_score as f32 / 10.0).round()
                ),
                "Cryptominer" => format!(
                    "Origin: {}\nType: Cryptocurrency Mining Malware\nCPU Usage: {}%\nTarget Coin: Monero\nSeverity: {}/10\nMitigation: Process isolation, update AV",
                    origin.country,
                    thermal_score + 30,
                    (thermal_score as f32 / 10.0).round()
                ),
                "System Exploit" => format!(
                    "Origin: {}\nType: Kernel-level Exploit\nTarget: Memory Access\nElevation: Root/System\nSeverity: {}/10\nMitigation: Patch system, isolate affected processes",
                    origin.country,
                    (kernel_score as f32 / 10.0).round()
                ),
                _ => "No details available".to_string()
            };
            
            threat_details.insert(detail_key, detail_value);
        }
    }
}

impl App for ThreatSentryApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request repaint regularly for animation
        ctx.request_repaint_after(Duration::from_millis(33)); // ~30 fps
        
        // Update 3D visualization and threat map data
        self.update_3d_system_activity();
        self.generate_threat_map_data();
        self.rotation_angle += 0.01;

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("ThreatSentry Ultra");
                ui.add_space(10.0);
                ui.label("Hardware-Powered Cyber Threat Intelligence");
                
                ui.with_layout(egui::Layout::right_to_left(egui::Align::RIGHT), |ui| {
                    let is_monitoring = *self.monitoring_data.is_monitoring.lock().unwrap();
                    if is_monitoring {
                        if ui.button("⏹ Stop").clicked() {
                            self.stop_monitoring();
                        }
                    } else {
                        if ui.button("▶ Start").clicked() {
                            self.start_monitoring();
                        }
                    }
                    ui.label(format!("Monitoring: {:.1}s", self.start_time.elapsed().as_secs_f64()));
                });
            });
            
            // Add tab strip for visualization modes
            ui.separator();
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.visualization_tab, 0, "Classic View");
                ui.selectable_value(&mut self.visualization_tab, 1, "3D Activity");
                ui.selectable_value(&mut self.visualization_tab, 2, "Threat Map");
                
                ui.with_layout(egui::Layout::right_to_left(egui::Align::RIGHT), |ui| {
                    ui.checkbox(&mut self.show_drill_down, "Threat Analysis");
                    ui.checkbox(&mut self.show_fft, "FFT Visualization");
                });
            });
        });

        // Make the central panel scrollable
        egui::CentralPanel::default().show(ctx, |ui| {
            // Add scrolling to the main panel
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.render_threat_scores(ui);
                
                ui.separator();
                
                // Display different visualization based on selected tab
                match self.visualization_tab {
                    0 => self.render_classic_view(ui),
                    1 => self.render_3d_visualization(ui),
                    2 => self.render_threat_map(ui),
                    _ => self.render_classic_view(ui),
                }
                
                // FFT Visualization (if enabled)
                if self.show_fft {
                    ui.separator();
                    self.render_fft_visualization(ui);
                }
                
                // Drill-down threat analysis
                if self.show_drill_down {
                    ui.separator();
                    self.render_threat_analysis(ui);
                }
            });
        });
    }
}

// Add these supporting methods
impl ThreatSentryApp {
    fn render_threat_scores(&self, ui: &mut egui::Ui) {
        ui.heading("Threat Scores");

        let mic_score = *self.monitoring_data.mic_score.lock().unwrap();
        let thermal_score = *self.monitoring_data.thermal_score.lock().unwrap();
        let kernel_score = *self.monitoring_data.kernel_score.lock().unwrap();
        let email_score = *self.monitoring_data.email_score.lock().unwrap();
        let combined_score = *self.monitoring_data.combined_score.lock().unwrap();

        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label("Microphone:");
                ui.label(format!("{}", mic_score));

                // Color indicator
                let color = if mic_score < 30 {
                    egui::Color32::GREEN
                } else if mic_score < 70 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::RED
                };

                ui.painter().rect_filled(
                    egui::Rect::from_min_size(
                        ui.cursor().min,
                        egui::Vec2::new(50.0, 20.0),
                    ),
                    0.0,
                    color,
                );
                ui.add_space(25.0);
            });

            ui.vertical(|ui| {
                ui.label("Thermal:");
                ui.label(format!("{}", thermal_score));

                // Color indicator
                let color = if thermal_score < 30 {
                    egui::Color32::GREEN
                } else if thermal_score < 70 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::RED
                };

                ui.painter().rect_filled(
                    egui::Rect::from_min_size(
                        ui.cursor().min,
                        egui::Vec2::new(50.0, 20.0),
                    ),
                    0.0,
                    color,
                );
                ui.add_space(25.0);
            });

            ui.vertical(|ui| {
                ui.label("Kernel:");
                ui.label(format!("{}", kernel_score));

                // Color indicator
                let color = if kernel_score < 30 {
                    egui::Color32::GREEN
                } else if kernel_score < 70 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::RED
                };

                ui.painter().rect_filled(
                    egui::Rect::from_min_size(
                        ui.cursor().min,
                        egui::Vec2::new(50.0, 20.0),
                    ),
                    0.0,
                    color,
                );
                ui.add_space(25.0);
            });

            ui.vertical(|ui| {
                ui.label("Email:");
                ui.label(format!("{}", email_score));

                // Color indicator
                let color = if email_score < 30 {
                    egui::Color32::GREEN
                } else if email_score < 70 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::RED
                };

                ui.painter().rect_filled(
                    egui::Rect::from_min_size(
                        ui.cursor().min,
                        egui::Vec2::new(50.0, 20.0),
                    ),
                    0.0,
                    color,
                );
                ui.add_space(25.0);
            });

            ui.vertical(|ui| {
                ui.label("Combined:");
                ui.label(format!("{}", combined_score));

                // Color indicator
                let color = if combined_score < 30 {
                    egui::Color32::GREEN
                } else if combined_score < 70 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::RED
                };

                ui.painter().rect_filled(
                    egui::Rect::from_min_size(
                        ui.cursor().min,
                        egui::Vec2::new(50.0, 20.0),
                    ),
                    0.0,
                    color,
                );
                ui.add_space(25.0);
            });
        });
    }
    
    fn render_fft_visualization(&self, ui: &mut egui::Ui) {
        ui.heading("Frequency Spectrum Analysis");
                
        let fft_data = self.monitoring_data.fft_data.lock().unwrap().clone();
        if !fft_data.is_empty() {
            let points: PlotPoints = (0..fft_data.len())
                .map(|i| {
                    let freq = i as f64 * 22050.0 / fft_data.len() as f64; // Assuming 44.1kHz sample rate
                    [freq, fft_data[i] as f64]
                })
                .collect();
            
            // Highlight ultrasonic range
            let ultrasonic_start = 15000.0;
            let ultrasonic_end = 20000.0;
            
            Plot::new("fft_plot")
                .height(120.0)
                .view_aspect(3.0)
                .allow_zoom(true)
                .allow_drag(true)
                .legend(Legend::default().position(Corner::LeftTop))
                .show(ui, |plot_ui| {
                    // Draw the full spectrum
                    plot_ui.line(Line::new(points).name("Frequency Spectrum").color(Color32::LIGHT_BLUE));
                    
                    // Highlight ultrasonic range
                    plot_ui.vline(egui_plot::VLine::new(ultrasonic_start).color(Color32::RED).width(1.0));
                    plot_ui.vline(egui_plot::VLine::new(ultrasonic_end).color(Color32::RED).width(1.0));
                });
        } else {
            ui.label("No frequency data available. Start monitoring to collect data.");
        }
    }
    
    fn render_threat_analysis(&self, ui: &mut egui::Ui) {
        ui.heading("Threat Analysis Drill-Down");
        
        let threat_origins = self.monitoring_data.threat_origins.lock().unwrap().clone();
        let mut selected_threat = self.monitoring_data.selected_threat.lock().unwrap();
        let threat_details = self.monitoring_data.threat_details.lock().unwrap().clone();
        
        if threat_origins.is_empty() {
            ui.label("No active threats detected for analysis.");
        } else {
            // Show the list of threats
            egui::Grid::new("threats_grid").num_columns(4).striped(true).show(ui, |ui| {
                ui.strong("Origin");
                ui.strong("Threat Type");
                ui.strong("Count");
                ui.strong("Action");
                ui.end_row();
                
                for origin in &threat_origins {
                    ui.label(&origin.country);
                    ui.label(&origin.threat_type);
                    ui.label(format!("{}", origin.threat_count));
                    
                    let detail_key = format!("{}: {}", origin.country, origin.threat_type);
                    if ui.button("Analyze").clicked() {
                        *selected_threat = Some(detail_key.clone());
                    }
                    ui.end_row();
                }
            });
            
            // Show details for selected threat
            if let Some(ref key) = *selected_threat {
                if let Some(details) = threat_details.get(key) {
                    ui.separator();
                    ui.strong(format!("Analysis: {}", key));
                    ui.add_space(5.0);
                    
                    let mut text = details.clone();
                    if text.contains("Mitigation:") {
                        // Extract and highlight mitigation steps
                        let parts: Vec<&str> = text.split("Mitigation:").collect();
                        if parts.len() > 1 {
                            text = format!("{}\n\nRecommended Action:\n{}", 
                                parts[0], 
                                parts[1].trim()
                            );
                        }
                    }
                    
                    egui::Frame::dark_canvas(ui.style()).show(ui, |ui| {
                        ui.label(text);
                    });
                    
                    // Action buttons
                    ui.horizontal(|ui| {
                        if ui.button("Isolate Threat").clicked() {
                            // This would actually perform isolation in a real implementation
                        }
                        if ui.button("Generate Report").clicked() {
                            // This would generate a report in a real implementation
                        }
                        if ui.button("Close Analysis").clicked() {
                            *selected_threat = None;
                        }
                    });
                }
            }
        }
    }
    
    fn render_classic_view(&self, ui: &mut egui::Ui) {
        // Temperature graph
        ui.heading("Temperature History");

        let temp_history = self.monitoring_data.temperature_history.lock().unwrap().clone();
        let time_history = self.monitoring_data.time_history.lock().unwrap().clone();

        if !temp_history.is_empty() && temp_history.len() == time_history.len() {
            let points: PlotPoints = (0..temp_history.len())
                .map(|i| [time_history[i], temp_history[i] as f64])
                .collect();

            let line = Line::new(points).name("Temperature (°C)");

            Plot::new("temperature_plot")
                .view_aspect(3.0)
                .show(ui, |plot_ui| {
                    plot_ui.line(line);
                });
        } else {
            ui.label("No temperature data yet");
        }

        ui.separator();

        // Microphone power graph
        ui.heading("Microphone Activity");

        let mic_history = self.monitoring_data.mic_power_history.lock().unwrap().clone();

        if !mic_history.is_empty() && mic_history.len() == time_history.len() {
            let points: PlotPoints = (0..mic_history.len())
                .map(|i| [time_history[i], mic_history[i] as f64])
                .collect();

            let line = Line::new(points).name("Microphone Power");

            Plot::new("microphone_plot")
                .view_aspect(3.0)
                .show(ui, |plot_ui| {
                    plot_ui.line(line);
                });
        } else {
            ui.label("No microphone data yet");
        }

        ui.separator();

        // Email URLs
        ui.heading("Detected URLs");

        let urls = self.monitoring_data.urls.lock().unwrap().clone();

        if !urls.is_empty() {
            for (url, score) in urls {
                let color = if score < 30 {
                    egui::Color32::GREEN
                } else if score < 70 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::RED
                };

                ui.horizontal(|ui| {
                    ui.colored_label(color, format!("[{}]", score));
                    ui.label(url);
                });
            }
        } else {
            ui.label("No URLs detected yet");
        }

        ui.separator();

        // Suspicious Processes
        ui.heading("Suspicious Processes");

        let processes = self.monitoring_data.suspicious_processes.lock().unwrap().clone();

        if !processes.is_empty() {
            for process in processes {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::YELLOW, "⚠");
                    ui.label(process);
                });
            }
        } else {
            ui.label("No suspicious processes detected");
        }

        ui.separator();

        // USB Devices
        ui.heading("USB Devices");

        let devices = self.monitoring_data.new_usb_devices.lock().unwrap().clone();

        if !devices.is_empty() {
            for device in devices {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::YELLOW, "⚠");
                    ui.label(device);
                });
            }
        } else {
            ui.label("No USB devices detected");
        }
    }
    
    fn render_3d_visualization(&mut self, ui: &mut egui::Ui) {
        ui.heading("Real-time 3D System Activity Visualization");
        
        // Get system activity data
        let system_activity = self.monitoring_data.system_activity_3d.lock().unwrap().clone();
        
        // Draw the 3D visualization
        let (response, painter) = ui.allocate_painter(
            egui::vec2(ui.available_width(), 350.0),
            egui::Sense::click_and_drag(),
        );
        
        let rect = response.rect;
        let center_x = rect.center().x;
        let center_y = rect.center().y;
        
        // Draw coordinate axes
        let axis_length = 50.0;
        painter.line_segment(
            [egui::pos2(center_x - axis_length, center_y), egui::pos2(center_x + axis_length, center_y)],
            egui::Stroke::new(1.0, Color32::WHITE),
        );
        painter.line_segment(
            [egui::pos2(center_x, center_y - axis_length), egui::pos2(center_x, center_y + axis_length)],
            egui::Stroke::new(1.0, Color32::WHITE),
        );
        
        // Draw legend
        let legend_x = rect.right() - 120.0;
        let legend_y = rect.top() + 20.0;
        painter.circle_filled(egui::pos2(legend_x, legend_y), 4.0, Color32::from_rgb(255, 50, 50));
        painter.text(
            egui::pos2(legend_x + 10.0, legend_y), 
            egui::Align2::LEFT_CENTER, 
            "Microphone", 
            egui::FontId::default(), 
            Color32::WHITE,
        );
        
        painter.circle_filled(egui::pos2(legend_x, legend_y + 20.0), 4.0, Color32::from_rgb(255, 165, 0));
        painter.text(
            egui::pos2(legend_x + 10.0, legend_y + 20.0), 
            egui::Align2::LEFT_CENTER, 
            "Thermal", 
            egui::FontId::default(), 
            Color32::WHITE,
        );
        
        painter.circle_filled(egui::pos2(legend_x, legend_y + 40.0), 4.0, Color32::from_rgb(50, 100, 255));
        painter.text(
            egui::pos2(legend_x + 10.0, legend_y + 40.0), 
            egui::Align2::LEFT_CENTER, 
            "Kernel", 
            egui::FontId::default(), 
            Color32::WHITE,
        );
        
        // Sort points by Z for proper depth
        let mut sorted_points = system_activity.clone();
        sorted_points.sort_by(|a, b| a.z.partial_cmp(&b.z).unwrap());
        
        // Draw all points
        for point in sorted_points.iter() {
            Self::draw_3d_point(ui, center_x, center_y, point, 15.0);
        }
        
        // Draw overlay text showing activity status
        let mic_score = *self.monitoring_data.mic_score.lock().unwrap();
        let thermal_score = *self.monitoring_data.thermal_score.lock().unwrap();
        let kernel_score = *self.monitoring_data.kernel_score.lock().unwrap();
        
        ui.vertical(|ui| {
            ui.add_space(300.0); // Push below the visualization
            
            egui::Grid::new("activity_grid").show(ui, |ui| {
                let text_color = |score: u8| -> Color32 {
                    match score {
                        0..=30 => Color32::GREEN,
                        31..=70 => Color32::YELLOW,
                        _ => Color32::RED,
                    }
                };
                
                ui.strong("Microphone Activity:");
                ui.colored_label(text_color(mic_score), format!("{}/100", mic_score));
                ui.end_row();
                
                ui.strong("Thermal Activity:");
                ui.colored_label(text_color(thermal_score), format!("{}/100", thermal_score));
                ui.end_row();
                
                ui.strong("Kernel Activity:");
                ui.colored_label(text_color(kernel_score), format!("{}/100", kernel_score));
                ui.end_row();
            });
        });
    }
    
    fn render_threat_map(&self, ui: &mut egui::Ui) {
        ui.heading("Global Threat Origin Map");
        
        // Get threat origins data
        let threat_origins = self.monitoring_data.threat_origins.lock().unwrap().clone();
        
        // Draw a simplified world map
        let (response, painter) = ui.allocate_painter(
            egui::vec2(ui.available_width(), 350.0),
            egui::Sense::click_and_drag(),
        );
        
        let rect = response.rect;
        
        // Draw a basic world map outline (very simplified)
        painter.rect_filled(rect, 0.0, Color32::from_rgb(10, 20, 40)); // Dark blue background
        
        // Draw continent outlines (very simplified)
        let continents = [
            // North America
            vec![
                [0.1, 0.2], [0.2, 0.2], [0.3, 0.3], [0.25, 0.4], [0.2, 0.45], [0.1, 0.3]
            ],
            // South America
            vec![
                [0.25, 0.5], [0.3, 0.5], [0.35, 0.7], [0.25, 0.8], [0.2, 0.6]
            ],
            // Europe
            vec![
                [0.45, 0.2], [0.55, 0.2], [0.55, 0.35], [0.45, 0.35]
            ],
            // Africa
            vec![
                [0.45, 0.4], [0.55, 0.4], [0.55, 0.7], [0.45, 0.7]
            ],
            // Asia
            vec![
                [0.55, 0.2], [0.8, 0.2], [0.8, 0.5], [0.6, 0.5], [0.55, 0.4]
            ],
            // Australia
            vec![
                [0.8, 0.6], [0.9, 0.6], [0.9, 0.7], [0.8, 0.7]
            ],
        ];
        
        for continent in continents.iter() {
            let points: Vec<egui::Pos2> = continent.iter()
                .map(|[x, y]| {
                    egui::pos2(
                        rect.left() + x * rect.width(),
                        rect.top() + y * rect.height()
                    )
                })
                .collect();
            
            painter.add(egui::Shape::Path(egui::epaint::PathShape::closed_line(
                points,
                egui::Stroke::new(1.0, Color32::from_rgb(40, 80, 120))
            )));
        }
        
        // Draw threat points
        for origin in threat_origins.iter() {
            // Convert lat/long to x/y coordinates (simple mapping)
            // Note: real implementation would use proper map projection
            let x = rect.left() + ((origin.longitude + 180.0) / 360.0) * rect.width();
            let y = rect.top() + ((origin.latitude + 90.0) / 180.0) * rect.height();
            
            // Determine color based on threat type
            let color = match origin.threat_type.as_str() {
                "Phishing" => Color32::from_rgb(255, 100, 100),
                "Ultrasonic Beacon" => Color32::from_rgb(255, 255, 100),
                "Cryptominer" => Color32::from_rgb(255, 165, 0),
                "System Exploit" => Color32::from_rgb(255, 50, 255),
                _ => Color32::WHITE,
            };
            
            // Draw threat point
            let size = 5.0 + (origin.threat_count as f32).min(10.0);
            painter.circle_filled(egui::pos2(x, y), size, color);
            
            // Draw threat label
            painter.text(
                egui::pos2(x + size + 5.0, y), 
                egui::Align2::LEFT_CENTER, 
                &origin.country, 
                egui::FontId::default(), 
                Color32::WHITE,
            );
        }
        
        // Draw legend
        let legend_x = rect.right() - 150.0;
        let legend_y = rect.top() + 20.0;
        
        let threat_types = [
            ("Phishing", Color32::from_rgb(255, 100, 100)),
            ("Ultrasonic", Color32::from_rgb(255, 255, 100)),
            ("Cryptominer", Color32::from_rgb(255, 165, 0)),
            ("System Exploit", Color32::from_rgb(255, 50, 255)),
        ];
        
        for (i, (threat_type, color)) in threat_types.iter().enumerate() {
            let y_pos = legend_y + (i as f32 * 20.0);
            painter.circle_filled(egui::pos2(legend_x, y_pos), 4.0, *color);
            painter.text(
                egui::pos2(legend_x + 10.0, y_pos), 
                egui::Align2::LEFT_CENTER, 
                threat_type, 
                egui::FontId::default(), 
                Color32::WHITE,
            );
        }
        
        // Statistics
        ui.vertical(|ui| {
            ui.add_space(320.0); // Push below the map
            
            let total_threats = threat_origins.iter().map(|o| o.threat_count).sum::<i32>();
            
            // Show threat statistics
            ui.horizontal(|ui| {
                ui.strong(format!("Active Threats: {}", threat_origins.len()));
                ui.separator();
                ui.strong(format!("Total Attacks: {}", total_threats));
                ui.separator();
                
                if !threat_origins.is_empty() {
                    let most_active = threat_origins.iter()
                        .max_by_key(|o| o.threat_count)
                        .unwrap();
                    ui.strong(format!("Most Active: {} ({})", most_active.country, most_active.threat_count));
                }
            });
            
            if !threat_origins.is_empty() {
                ui.label("Click 'Threat Analysis' for detailed examination of each threat vector.");
            }
        });
    }
}

pub fn run_gui(username: String, password: String) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 600.0])
            .with_resizable(true),
        vsync: true,
        ..Default::default()
    };

    eframe::run_native(
        "ThreatSentry Ultra",
        options,
        Box::new(|_cc| Box::new(ThreatSentryApp::new(username, password)))
    )
}
