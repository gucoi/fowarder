#[derive(Debug, Default)]
pub struct ForwarderMetrics {
    pub packets_received: u64,
    pub packets_forwarded: u64,
    pub packets_dropped: u64,
    pub bytes_forwarded: u64,
    pub forward_errors: u64,
    pub retry_count: u64,
    pub last_forward_time: Option<SystemTime>,
}
