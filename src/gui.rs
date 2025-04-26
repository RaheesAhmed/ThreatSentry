use eframe::{egui, App};
use egui_plot::{Line, Plot, PlotPoints};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::thread;

use crate::email_monitor::EmailMonitor;
use crate::mic_monitor::MicMonitor;
use crate::thermal_monitor::ThermalMonitor;
use crate::kernel_monitor::KernelMonitor;

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
        }
    }
}

pub struct ThreatSentryApp {
    monitoring_data: MonitoringData,
    start_time: Instant,
    username: String,
    password: String,
}

impl ThreatSentryApp {
    pub fn new(username: String, password: String) -> Self {
        ThreatSentryApp {
            monitoring_data: MonitoringData::new(),
            start_time: Instant::now(),
            username,
            password,
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

                // Get microphone score
                let mic_score_val = mic_monitor.get_threat_score();
                *mic_score.lock().unwrap() = mic_score_val;

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

                // Add microphone power (simulated for now)
                let power = if mic_score_val > 0 {
                    (mic_score_val as f32) / 200.0 + 0.05
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
                        },
                        Err(e) => println!("Error fetching emails: {}", e),
                    }
                }

                // Calculate combined score
                let mic = *mic_score.lock().unwrap() as u16;
                let thermal = *thermal_score.lock().unwrap() as u16;
                let kernel = *kernel_score.lock().unwrap() as u16;
                let email = *email_score.lock().unwrap() as u16;
                let combined = (mic + thermal + kernel + email) / 4;
                *combined_score.lock().unwrap() = combined as u8;

                // Sleep for a short time
                thread::sleep(Duration::from_millis(500));
            }

            // Stop microphone monitoring
            mic_monitor.stop_monitoring();
        });
    }

    pub fn stop_monitoring(&self) {
        let mut is_monitoring = self.monitoring_data.is_monitoring.lock().unwrap();
        *is_monitoring = false;
    }
}

impl App for ThreatSentryApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("ThreatSentry Ultra");
            ui.label("Hardware-Powered Cyber Threat Intelligence");
            ui.separator();

            // Monitoring controls
            ui.horizontal(|ui| {
                let is_monitoring = *self.monitoring_data.is_monitoring.lock().unwrap();

                if is_monitoring {
                    if ui.button("Stop Monitoring").clicked() {
                        self.stop_monitoring();
                    }
                } else {
                    if ui.button("Start Monitoring").clicked() {
                        self.start_monitoring();
                    }
                }

                ui.label(format!("Monitoring time: {:.1} seconds", self.start_time.elapsed().as_secs_f64()));
            });

            ui.separator();

            // Threat scores
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

            ui.separator();

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
        });
    }
}

pub fn run_gui(username: String, password: String) -> Result<(), eframe::Error> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "ThreatSentry Ultra",
        native_options,
        Box::new(|_cc| Box::new(ThreatSentryApp::new(username, password)))
    )
}
