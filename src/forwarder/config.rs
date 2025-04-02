#[derive(Debug, Clone, Deserialize)]
pub struct ForwarderSettings {
    pub max_retries: u32,
    pub retry_interval: u64,
    pub connect_timeout: u64,
    pub buffer_size: usize,
    pub batch_size: usize,
}
