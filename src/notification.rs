use notify_rust::{Notification, Timeout};

pub struct NotificationManager;

impl NotificationManager {
    pub fn new() -> Self {
        NotificationManager
    }

    pub fn send_notification(&self, title: &str, message: &str, urgency: u8) -> Result<(), String> {
        // Determine notification timeout based on urgency
        let timeout = match urgency {
            0..=30 => Timeout::Milliseconds(3000),  // Low urgency
            31..=70 => Timeout::Milliseconds(5000), // Medium urgency
            _ => Timeout::Milliseconds(10000),      // High urgency
        };

        // Send notification
        match Notification::new()
            .summary(title)
            .body(message)
            .timeout(timeout)
            .show() {
                Ok(_) => Ok(()),
                Err(e) => Err(format!("Failed to send notification: {}", e)),
            }
    }
}
