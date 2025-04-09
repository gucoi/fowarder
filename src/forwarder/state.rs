use std::time::{SystemTime, Duration};

#[derive(Debug, Clone)]
pub enum ForwarderState {
    Initial,
    Running,
    Paused,
    Error(String),
    Shutdown,
}

impl ForwarderState {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Initial => 0,
            Self::Running => 1,
            Self::Paused => 2,
            Self::Error(_) => 3,
            Self::Shutdown => 4,
        }
    }
}

impl From<ForwarderState> for u8 {
    fn from(state: ForwarderState) -> Self {
        state.as_u8()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forwarder_state_to_u8() {
        assert_eq!(ForwarderState::Initial.as_u8(), 0);
        assert_eq!(ForwarderState::Running.as_u8(), 1);
        assert_eq!(ForwarderState::Paused.as_u8(), 2);
        assert_eq!(ForwarderState::Error("test".to_string()).as_u8(), 3);
        assert_eq!(ForwarderState::Shutdown.as_u8(), 4);
    }
}
