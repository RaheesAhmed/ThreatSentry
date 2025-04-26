mod email_monitor;
mod mic_monitor;
mod thermal_monitor;
mod notification;
mod gui;
mod kernel_monitor;

use clap::{Parser, Subcommand};
use colored::*;
use email_monitor::EmailMonitor;
use mic_monitor::MicMonitor;
use thermal_monitor::ThermalMonitor;
use kernel_monitor::KernelMonitor;
use notification::NotificationManager;
use std::{thread, time::Duration};
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Monitor emails for phishing attempts
    Email {
        /// Gmail username
        #[arg(short, long)]
        username: String,

        /// Gmail password or app password
        #[arg(short, long)]
        password: String,

        /// Number of recent emails to check
        #[arg(short, long, default_value_t = 5)]
        limit: usize,
    },

    /// Monitor microphone for high-frequency signals
    Mic {
        /// Duration to monitor in seconds
        #[arg(short, long, default_value_t = 10)]
        duration: u64,
    },

    /// Monitor system temperature for anomalies
    Thermal {
        /// Duration to monitor in seconds
        #[arg(short, long, default_value_t = 30)]
        duration: u64,
    },

    /// Monitor system processes and USB devices
    Kernel {
        /// Duration to monitor in seconds
        #[arg(short, long, default_value_t = 60)]
        duration: u64,
    },

    /// Run all monitoring systems
    Full {
        /// Gmail username
        #[arg(short, long)]
        username: Option<String>,

        /// Gmail password or app password
        #[arg(short, long)]
        password: Option<String>,

        /// Duration to monitor in seconds
        #[arg(short, long, default_value_t = 60)]
        duration: u64,
    },

    /// Launch the graphical user interface
    Gui {
        /// Gmail username
        #[arg(short, long)]
        username: String,

        /// Gmail password or app password
        #[arg(short, long)]
        password: String,
    },
}

fn main() {
    print_banner();

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Email { username, password, limit }) => {
            run_email_monitor(username, password, *limit);
        },
        Some(Commands::Mic { duration }) => {
            run_mic_monitor(*duration);
        },
        Some(Commands::Thermal { duration }) => {
            run_thermal_monitor(*duration);
        },
        Some(Commands::Kernel { duration }) => {
            run_kernel_monitor(*duration);
        },
        Some(Commands::Full { username, password, duration }) => {
            run_full_scan(username, password, *duration);
        },
        Some(Commands::Gui { username, password }) => {
            run_gui(username, password);
        },
        None => {
            println!("{}", "No command specified. Use --help for usage information.".yellow());
        }
    }
}

fn print_banner() {
    println!("{}", r"
 _____ _                    _   _____            _              _   _ _ _
|_   _| |                  | | /  ___|          | |            | | | | | |
  | | | |__  _ __ ___  __ _| |_\ `--.  ___ _ __ | |_ _ __ _   _| | | | | |_ _ __ __ _
  | | | '_ \| '__/ _ \/ _` | __|`--. \/ _ \ '_ \| __| '__| | | | | | | | __| '__/ _` |
  | | | | | | | |  __/ (_| | |_/\__/ /  __/ | | | |_| |  | |_| | |_| | | |_| | | (_| |
  \_/ |_| |_|_|  \___|\__,_|\__\____/ \___|_| |_|\__|_|   \__, |\___/|_|\__|_|  \__,_|
                                                            __/ |
                                                           |___/
    ".bright_cyan());
    println!("{}", "Hardware-Powered Cyber Threat Intelligence".bright_green());
    println!("{}", "---------------------------------------------".bright_blue());
}

fn run_email_monitor(username: &str, password: &str, limit: usize) {
    println!("{}", "\n[EMAIL MONITOR]".bright_blue());
    println!("Scanning {} recent emails for threats...", limit);

    let email_monitor = EmailMonitor::new(
        username.to_string(),
        password.to_string(),
        "imap.gmail.com".to_string(),
    );

    // Fetch emails
    let emails = match email_monitor.fetch_emails(limit) {
        Ok(emails) => emails,
        Err(e) => {
            println!("{} {}", "Error fetching emails:".bright_red(), e);
            return;
        }
    };

    // Extract and scan URLs
    let urls = email_monitor.extract_urls(emails);
    let scored_urls = email_monitor.scan_urls(urls);

    // Display results
    println!("\nResults:");
    for (url, score) in scored_urls {
        let score_color = match score {
            0..=30 => score.to_string().green(),
            31..=70 => score.to_string().yellow(),
            _ => score.to_string().red(),
        };

        println!("URL: {} | Threat Score: {}", url, score_color);

        // Send notification for high-risk URLs
        if score > 50 {
            let notification_manager = NotificationManager::new();
            let _ = notification_manager.send_notification(
                "ThreatSentry Ultra",
                &format!("Suspicious URL detected: {}", url),
                score,
            );
        }
    }
}

fn run_mic_monitor(duration: u64) {
    println!("{}", "\n[MICROPHONE MONITOR]".bright_blue());
    println!("Monitoring microphone for high-frequency signals for {} seconds...", duration);

    let mic_monitor = MicMonitor::new();

    // Start monitoring
    match mic_monitor.start_monitoring() {
        Ok(_) => {
            // Show progress bar
            let pb = ProgressBar::new(duration);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} seconds")
                .unwrap()
                .progress_chars("#>-"));

            for _ in 0..duration {
                thread::sleep(Duration::from_secs(1));
                pb.inc(1);
            }

            pb.finish_with_message("Monitoring complete");

            // Stop monitoring and get results
            mic_monitor.stop_monitoring();
            let score = mic_monitor.get_threat_score();

            // Display results
            let score_color = match score {
                0..=30 => score.to_string().green(),
                31..=70 => score.to_string().yellow(),
                _ => score.to_string().red(),
            };

            println!("\nResults:");
            println!("Mic Threat Score: {}", score_color);

            // Send notification for high scores
            if score > 50 {
                let notification_manager = NotificationManager::new();
                let _ = notification_manager.send_notification(
                    "ThreatSentry Ultra",
                    "High-frequency audio signal detected!",
                    score,
                );
            }
        },
        Err(e) => {
            println!("{} {}", "Error starting microphone monitoring:".bright_red(), e);
        }
    }
}

fn run_thermal_monitor(duration: u64) {
    println!("{}", "\n[THERMAL MONITOR]".bright_blue());
    println!("Monitoring system temperature for {} seconds...", duration);

    let mut thermal_monitor = ThermalMonitor::new();

    // Show progress bar
    let pb = ProgressBar::new(duration);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} seconds")
        .unwrap()
        .progress_chars("#>-"));

    for _ in 0..duration {
        match thermal_monitor.check_temperature() {
            Ok(temp) => {
                pb.set_message(format!("Current temperature: {:.1}°C", temp));
            },
            Err(e) => {
                println!("{} {}", "Error checking temperature:".bright_red(), e);
            }
        }

        thread::sleep(Duration::from_secs(1));
        pb.inc(1);
    }

    pb.finish_with_message("Monitoring complete");

    // Get results
    let score = thermal_monitor.get_threat_score();

    // Display results
    let score_color = match score {
        0..=30 => score.to_string().green(),
        31..=70 => score.to_string().yellow(),
        _ => score.to_string().red(),
    };

    println!("\nResults:");
    println!("Thermal Threat Score: {}", score_color);

    // Send notification for high scores
    if score > 50 {
        let notification_manager = NotificationManager::new();
        let _ = notification_manager.send_notification(
            "ThreatSentry Ultra",
            "Temperature spike detected! Possible crypto-miner activity.",
            score,
        );
    }
}

fn run_kernel_monitor(duration: u64) {
    println!("{}", "\n[KERNEL TELEMETRY]".bright_blue());
    println!("Monitoring system processes and USB devices for {} seconds...", duration);

    let kernel_monitor = KernelMonitor::new();
    let notification_manager = NotificationManager::new();

    // Start monitoring
    match kernel_monitor.start_monitoring() {
        Ok(_) => println!("Kernel monitoring started successfully"),
        Err(e) => {
            println!("{} {}", "Error starting kernel monitoring:".bright_red(), e);
            return;
        }
    }

    // Create a progress bar
    let pb = ProgressBar::new(duration);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} seconds")
        .unwrap()
        .progress_chars("#>-"));

    for i in 0..duration {
        // Get suspicious processes
        let suspicious_processes = kernel_monitor.get_suspicious_processes();
        if !suspicious_processes.is_empty() {
            println!("\nSuspicious processes detected:");
            for process in &suspicious_processes {
                println!("  - {} (PID: {}, CPU: {:.1}%, Score: {})",
                    process.name.bright_yellow(),
                    process.pid,
                    process.cpu_usage,
                    colorize_score(process.suspicious_score));
            }
        }

        // Get new USB devices
        let new_usb_devices = kernel_monitor.get_new_usb_devices();
        if !new_usb_devices.is_empty() {
            println!("\nNew USB devices detected:");
            for device in &new_usb_devices {
                println!("  - {} (ID: {})",
                    device.description.bright_yellow(),
                    device.device_id);
            }

            // Send notification for new USB devices
            let _ = notification_manager.send_notification(
                "USB Device Detected",
                &format!("{} new USB device(s) connected", new_usb_devices.len()),
                50,
            );
        }

        // Sleep for 1 second
        if i < duration - 1 {
            thread::sleep(Duration::from_secs(1));
        }

        pb.inc(1);
    }

    pb.finish_with_message("Monitoring complete");

    // Stop monitoring
    kernel_monitor.stop_monitoring();

    // Get threat score
    let score = kernel_monitor.get_threat_score();

    // Display results
    println!("\nResults:");
    println!("Kernel Threat Score: {}", colorize_score(score));

    // Send notification for high scores
    if score > 50 {
        let _ = notification_manager.send_notification(
            "ThreatSentry Ultra",
            "Suspicious process or USB activity detected!",
            score,
        );
    }
}

fn run_full_scan(username: &Option<String>, password: &Option<String>, duration: u64) {
    println!("{}", "\n[FULL SYSTEM SCAN]".bright_blue());
    println!("Running comprehensive threat scan for {} seconds...", duration);

    // Initialize monitors
    let mic_monitor = MicMonitor::new();
    let mut thermal_monitor = ThermalMonitor::new();
    let kernel_monitor = KernelMonitor::new();

    // Start microphone monitoring
    match mic_monitor.start_monitoring() {
        Ok(_) => {
            println!("{}", "Microphone monitoring started".green());
        },
        Err(e) => {
            println!("{} {}", "Error starting microphone monitoring:".bright_red(), e);
        }
    }

    // Start kernel monitoring
    match kernel_monitor.start_monitoring() {
        Ok(_) => {
            println!("{}", "Kernel monitoring started".green());
        },
        Err(e) => {
            println!("{} {}", "Error starting kernel monitoring:".bright_red(), e);
        }
    }

    // Show progress bar
    let pb = ProgressBar::new(duration);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} seconds")
        .unwrap()
        .progress_chars("#>-"));

    for _ in 0..duration {
        // Check temperature
        match thermal_monitor.check_temperature() {
            Ok(temp) => {
                pb.set_message(format!("Current temperature: {:.1}°C", temp));
            },
            Err(e) => {
                println!("{} {}", "Error checking temperature:".bright_red(), e);
            }
        }

        thread::sleep(Duration::from_secs(1));
        pb.inc(1);
    }

    pb.finish_with_message("Monitoring complete");

    // Stop microphone monitoring
    mic_monitor.stop_monitoring();

    // Stop kernel monitoring
    kernel_monitor.stop_monitoring();

    // Get results
    let mic_score = mic_monitor.get_threat_score();
    let thermal_score = thermal_monitor.get_threat_score();
    let kernel_score = kernel_monitor.get_threat_score();

    // Run email scan if credentials provided
    let mut email_score = 0;
    if let (Some(username), Some(password)) = (username, password) {
        println!("\nScanning emails...");

        let email_monitor = EmailMonitor::new(
            username.to_string(),
            password.to_string(),
            "imap.gmail.com".to_string(),
        );

        // Fetch emails
        match email_monitor.fetch_emails(5) {
            Ok(emails) => {
                // Extract and scan URLs
                let urls = email_monitor.extract_urls(emails);
                let scored_urls = email_monitor.scan_urls(urls);

                // Display results and get highest score
                println!("\nEmail Results:");
                for (url, score) in &scored_urls {
                    let score_color = match score {
                        0..=30 => score.to_string().green(),
                        31..=70 => score.to_string().yellow(),
                        _ => score.to_string().red(),
                    };

                    println!("URL: {} | Threat Score: {}", url, score_color);

                    // Update highest score
                    if *score > email_score {
                        email_score = *score;
                    }
                }
            },
            Err(e) => {
                println!("{} {}", "Error fetching emails:".bright_red(), e);
            }
        }
    }

    // Calculate combined threat score
    let combined_score = (mic_score as u16 + thermal_score as u16 + kernel_score as u16 + email_score as u16) / 4;

    // Display final results
    println!("\n{}", "FINAL RESULTS".bright_yellow());
    println!("---------------------");
    println!("Microphone Threat Score: {}", colorize_score(mic_score));
    println!("Thermal Threat Score: {}", colorize_score(thermal_score));
    println!("Kernel Threat Score: {}", colorize_score(kernel_score));
    println!("Email Threat Score: {}", colorize_score(email_score));
    println!("---------------------");
    println!("Combined Threat Score: {}", colorize_score(combined_score as u8));

    // Send notification for high combined score
    if combined_score > 50 {
        let notification_manager = NotificationManager::new();
        let _ = notification_manager.send_notification(
            "ThreatSentry Ultra",
            &format!("High threat level detected! Score: {}", combined_score),
            combined_score as u8,
        );
    }
}

fn colorize_score(score: u8) -> colored::ColoredString {
    match score {
        0..=30 => score.to_string().green(),
        31..=70 => score.to_string().yellow(),
        _ => score.to_string().red(),
    }
}

fn run_gui(username: &str, password: &str) {
    println!("{}", "\n[GUI]".bright_blue());
    println!("Launching ThreatSentry Ultra GUI...");

    match gui::run_gui(username.to_string(), password.to_string()) {
        Ok(_) => println!("GUI closed successfully."),
        Err(e) => println!("{} {}", "Error running GUI:".bright_red(), e),
    }
}
