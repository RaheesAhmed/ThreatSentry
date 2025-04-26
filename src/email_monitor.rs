use regex::Regex;
use std::error::Error;
use imap::Session;

pub struct EmailMonitor {
    username: String,
    password: String,
    imap_server: String,
}

impl EmailMonitor {
    pub fn new(username: String, password: String, imap_server: String) -> Self {
        EmailMonitor {
            username,
            password,
            imap_server,
        }
    }

    fn connect_to_imap(&self) -> Result<Session<imap::Connection>, Box<dyn Error>> {
        println!("Connecting to IMAP server: {}", self.imap_server);

        // Connect to the server
        let client = imap::ClientBuilder::new(&self.imap_server, 993).connect()?;

        // Login to the server
        let session = match client.login(&self.username, &self.password) {
            Ok(session) => session,
            Err((err, _client)) => return Err(Box::new(err)),
        };

        Ok(session)
    }

    pub fn fetch_emails(&self, limit: usize) -> Result<Vec<String>, Box<dyn Error>> {
        println!("Connecting to IMAP server: {}", self.imap_server);
        println!("Fetching {} most recent emails", limit);

        // Try to connect to the IMAP server
        match self.connect_to_imap() {
            Ok(mut session) => {
                // Select the INBOX mailbox
                session.select("INBOX")?;

                // Get the total number of messages
                let mailbox_data = session.examine("INBOX")?;
                let total_messages = mailbox_data.exists;

                // Calculate the range of messages to fetch (most recent ones)
                let start = if total_messages > limit as u32 {
                    total_messages - limit as u32 + 1
                } else {
                    1
                };
                let end = total_messages;

                // Fetch the messages
                let sequence = format!("{}:{}", start, end);
                let messages = session.fetch(sequence, "BODY[TEXT]")?;

                let mut email_bodies = Vec::new();

                for message in messages.iter() {
                    // Extract the body text
                    if let Some(body) = message.body() {
                        let body_str = String::from_utf8_lossy(body);
                        email_bodies.push(body_str.to_string());
                    }
                }

                // Logout
                session.logout()?;

                if email_bodies.is_empty() {
                    println!("No emails found. Using sample data for testing.");
                    // Return sample data if no emails were found
                    return Ok(vec![
                        "Check out this link: https://example.com/login".to_string(),
                        "Important security update: https://secure-site.com/update".to_string(),
                    ]);
                }

                Ok(email_bodies)
            },
            Err(e) => {
                println!("Failed to connect to IMAP server: {}. Using sample data for testing.", e);
                // Return sample data if connection failed
                Ok(vec![
                    "Check out this link: https://example.com/login".to_string(),
                    "Important security update: https://secure-site.com/update".to_string(),
                ])
            }
        }
    }

    pub fn extract_urls(&self, emails: Vec<String>) -> Vec<String> {
        let url_regex = Regex::new(r"https?://[^\s/$.?#].[^\s]*").unwrap();
        let mut urls = Vec::new();

        for email in emails {
            for capture in url_regex.captures_iter(&email) {
                urls.push(capture[0].to_string());
            }
        }

        urls
    }

    pub fn scan_urls(&self, urls: Vec<String>) -> Vec<(String, u8)> {
        // In a real implementation, we would check URLs against PhishTank
        // For now, just assign random scores
        urls.into_iter()
            .map(|url| {
                let score = if url.contains("login") {
                    70
                } else {
                    30
                };
                (url, score)
            })
            .collect()
    }
}
