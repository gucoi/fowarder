use std::time::{SystemTime, Duration};

#[derive(Debug, Clone)]
pub enum ForwarderState {
    Initial,
    Running,
    Paused,
    Error(String),
    Shutdown,
}

#[derive(Debug)]
pub struct ForwarderStatus {
    pub state: ForwarderState,
    pub last_active: SystemTime,
    pub retry_count: u32,
    pub connected: bool,
    pub uptime: Duration,
    pub last_error: Option<String>,
    pub packets_in_queue: usize,
}

impl ForwarderStatus {
    pub fn new() -> Self {
        Self {
            state: ForwarderState::Initial,
            last_active: SystemTime::now(),
            retry_count: 0,
            connected: false,
            uptime: Duration::from_secs(0),
            last_error: None,
            packets_in_queue: 0,
        }
    }
}
