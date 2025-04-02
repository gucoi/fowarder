use std::sync::atomic::{AtomicU64, Ordering};
use crate::protocol::common::PacketStats;

pub struct MetricsCollector {
    packet_counter: AtomicU64,
    bytes_counter: AtomicU64,
    error_counter: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        MetricsCollector {
            packet_counter: AtomicU64::new(0),
            bytes_counter: AtomicU64::new(0),
            error_counter: AtomicU64::new(0),
        }
    }

    pub fn update(&self, bytes: u64, success: bool) {
        self.packet_counter.fetch_add(1, Ordering::Relaxed);
        if success {
            self.bytes_counter.fetch_add(bytes, Ordering::Relaxed);
        } else {
            self.error_counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}
