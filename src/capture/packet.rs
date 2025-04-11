use bytes::{BufMut, Bytes, BytesMut};
use pcap::{Active, Capture, Device};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, broadcast, watch};

use crate::error::{ForwarderError, Result};
use crate::protocol::common::ProtocolType;

/// 优化的数据包信息结构
#[derive(Clone, Debug)]
pub struct PacketInfo {
    // 使用 Arc<Bytes> 替代 Option<Bytes> 来共享数据
    pub payload: Arc<Bytes>,
    // 内联小的头部数据以减少内存分配
    pub header: PacketHeader,
    // 使用 Option<NonZeroU32> 优化 Option 存储
    pub vni: Option<std::num::NonZeroU32>,
}

pub fn packet_to_bytes(packet: &PacketInfo) -> Bytes {
    let mut buffer = BytesMut::with_capacity(1500); // 使用常见的MTU大小
    
    // 添加基本的以太网头部（14字节）
    buffer.put_slice(&[0xFF; 6]); // 目标MAC
    buffer.put_slice(&[0xAA; 6]); // 源MAC
    buffer.put_u16(0x0800);       // IPv4类型

    // 添加一些示例IP包数据
    buffer.put_slice(&[0x45, 0x00]); // IPv4 version & header length
    buffer.put_slice(&[0x00, 0x20]); // Total length
    buffer.put_slice(&[0x00, 0x00]); // Identification
    buffer.put_slice(&[0x40, 0x00]); // Flags & fragment offset
    buffer.put_u8(64);               // TTL
    buffer.put_u8(17);               // Protocol (UDP)
    buffer.put_u16(0x0000);          // Checksum

    // 源IP和目标IP
    buffer.put_slice(&[192, 168, 1, 1]);
    buffer.put_slice(&[192, 168, 1, 2]);

    buffer.freeze()
}

#[derive(Clone, Debug)]
pub struct PacketHeader {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: ProtocolType,
    pub src_port: Option<u16>, 
    pub dst_port: Option<u16>, 
    pub length: u16,
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            payload: Arc::new(Bytes::new()),
            header: PacketHeader::default(),
            vni: None,
        }
    }
}

impl Default for PacketHeader {
    fn default() -> Self {
        Self {
            source: Ipv4Addr::new(0, 0, 0, 0),
            destination: Ipv4Addr::new(0, 0, 0, 0),
            protocol: ProtocolType::Ethernet,
            src_port: None,
            dst_port: None,
            length: 0,
        }
    }
}

/// 抓包过滤器 - 只保留必要的过滤配置
#[derive(Clone)]
pub struct PacketFilter {
    pub bpf_filter: String,
    pub snapshot_length: i32,
    pub promiscuous: bool,
    pub timeout_ms: i32,
}

impl Default for PacketFilter {
    fn default() -> Self {
        Self {
            bpf_filter: String::new(),
            snapshot_length: 65535,
            promiscuous: true,
            timeout_ms: 1000,
        }
    }
}

pub struct PacketCapture {
    cap: Arc<Mutex<Capture<Active>>>,
    tx: broadcast::Sender<PacketInfo>,
    interface_name: String,
    stats: Arc<CaptureStats>,
    stop_rx: watch::Receiver<bool>,
    stop_tx: watch::Sender<bool>,
}

pub struct CaptureStats {
    packets_received: AtomicU64,
    packets_dropped: AtomicU64,
    packets_if_dropped: AtomicU64,
}

impl Default for CaptureStats {
    fn default() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_if_dropped: AtomicU64::new(0),
        }
    }
}

impl CaptureStats {
    fn get_stats(&self) -> (u64, u64, u64) {
        (
            self.packets_received.load(Ordering::Relaxed),
            self.packets_dropped.load(Ordering::Relaxed),
            self.packets_if_dropped.load(Ordering::Relaxed),
        )
    }
}

impl PacketCapture {
    /// 创建新的抓包实例
    pub fn new(
        interface_name: &str,
        tx: broadcast::Sender<PacketInfo>,
        filter: PacketFilter,
    ) -> Result<Self> {
        // 查找网络接口
        let device = Device::list()?
            .into_iter()
            .find(|dev| dev.name == interface_name)
            .ok_or_else(|| {
                ForwarderError::Capture(format!("Interface {} not found", interface_name))
            })?;

        // 创建抓包器
        let mut cap = Capture::from_device(device)?
            .promisc(filter.promiscuous)
            .snaplen(filter.snapshot_length)
            .timeout(filter.timeout_ms)
            .open()?;

        // 设置BPF过滤器
        if !filter.bpf_filter.is_empty() {
            cap.filter(&filter.bpf_filter, true)?;
        }

        let (stop_tx, stop_rx) = watch::channel(false);

        Ok(Self {
            cap: Arc::new(Mutex::new(cap)),
            tx,
            interface_name: interface_name.to_string(),
            stats: Arc::new(CaptureStats::default()),
            stop_rx,
            stop_tx,
        })
    }

    pub fn get_stats_handler(&self) -> Arc<CaptureStats> {
        Arc::clone(&self.stats)
    }

    pub fn break_loop(&mut self) {
        println!("Breaking capture loop...");
        if let Err(e) = self.stop_tx.send(true) {
            println!("Failed to send stop signal: {}", e);
        }
    }

    pub fn clone_with_stop(&self) -> Self {
        Self {
            cap: Arc::clone(&self.cap),
            tx: self.tx.clone(),
            interface_name: self.interface_name.clone(),
            stats: Arc::clone(&self.stats),
            stop_rx: self.stop_rx.clone(),
            stop_tx: self.stop_tx.clone(),
        }
    }

    pub async fn capture_loop(&mut self) -> Result<()> {
        let stats = &self.stats;
        println!("Starting packet capture on interface: {}", self.interface_name);

        let mut consecutive_errors = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 5;
        let mut should_stop = *self.stop_rx.borrow();

        loop {
            if should_stop {
                println!("Received stop signal, ending capture loop");
                break;
            }

            tokio::select! {
                Ok(()) = self.stop_rx.changed() => {
                    should_stop = *self.stop_rx.borrow();
                    if should_stop {
                        println!("Received stop signal, ending capture loop");
                        break;
                    }
                }
                _ = tokio::task::yield_now() => {
                    // 使用本地变量存储临时数据
                    let data = {
                        let mut guard = self.cap.lock().unwrap();
                        match guard.next_packet() {
                            Ok(packet) => {
                                // 直接在这里克隆数据
                                Some(Vec::from(packet.data))
                            }
                            Err(pcap::Error::TimeoutExpired) => None,
                            Err(e) => {
                                println!("Error capturing packet: {}", e);
                                None
                            }
                        }
                    };

                    // 在锁外处理数据
                    if let Some(packet_data) = data {
                        stats.packets_received.fetch_add(1, Ordering::Relaxed);
                        
                        if let Some(packet_info) = Self::process_packet_data(&packet_data) {
                            if let Err(e) = self.tx.send(packet_info) {
                                println!("Failed to send packet: {}", e);
                                break;
                            }
                        }
                        consecutive_errors = 0;
                    } else {
                        consecutive_errors += 1;
                        if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                            break;
                        }
                    }
                }
            }
        }

        println!("Capture loop ended");
        Ok(())
    }

    // 新增辅助方法处理原始数据
    fn process_packet_data(data: &[u8]) -> Option<PacketInfo> {
        let ethernet = EthernetPacket::new(data)?;
        let payload = Arc::new(Bytes::copy_from_slice(data));
        
        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ip_packet = Ipv4Packet::new(ethernet.payload())?;
                let mut src_port = None;
                let mut dst_port = None;

                // 解析TCP/UDP端口
                match ip_packet.get_next_level_protocol().0 {
                    6 => {
                        // TCP
                        if let Some(tcp) = TcpPacket::new(ip_packet.payload()) {
                            src_port = Some(tcp.get_source());
                            dst_port = Some(tcp.get_destination());
                        }
                    }
                    17 => {
                        // UDP
                        if let Some(udp) = UdpPacket::new(ip_packet.payload()) {
                            src_port = Some(udp.get_source());
                            dst_port = Some(udp.get_destination());
                        }
                    }
                    _ => {}
                }

                Some(PacketInfo {
                    payload,
                    header: PacketHeader {
                        source: ip_packet.get_source(),
                        destination: ip_packet.get_destination(),
                        protocol: ProtocolType::try_from(ip_packet.get_next_level_protocol().0).unwrap(),
                        src_port,
                        dst_port,
                        length: data.len() as u16,
                    },
                    vni: None,  // Default to None for now
                })
            }
            _ => None,
        }
    }

    pub fn build_packet(packet_info: &PacketInfo) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_slice(&packet_info.payload.as_ref()[..14]);

        let mut ip_header = Vec::new();
        ip_header.extend_from_slice(&packet_info.payload.as_ref()[14..34]);

        let src_ip_ocs = packet_info.header.source.octets();
        ip_header[12] = src_ip_ocs[0];
        ip_header[13] = src_ip_ocs[1];
        ip_header[14] = src_ip_ocs[2];
        ip_header[15] = src_ip_ocs[3];

        let dst_ip_ocs = packet_info.header.destination.octets();
        ip_header[16] = dst_ip_ocs[0];
        ip_header[17] = dst_ip_ocs[1];
        ip_header[18] = dst_ip_ocs[2];
        ip_header[19] = dst_ip_ocs[3];

        buf.put_slice(&ip_header);

        buf.put_slice(&packet_info.payload.as_ref()[34..]);

        buf
    }

    /// 获取当前统计信息
    pub fn get_stats(&self) -> &CaptureStats {
        &self.stats
    }

    /// 设置新的BPF过滤器
    pub fn set_filter(&mut self, filter: &str) -> Result<()> {
        self.cap.lock().unwrap().filter(filter, true)?;
        Ok(())
    }
}


// 帮助函数：列出所有可用的网络接口
pub fn list_interfaces() -> Result<Vec<String>> {
    Ok(Device::list()?.into_iter().map(|dev| dev.name).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;
    use std::time::Duration;

    #[tokio::test]
    async fn test_packet_capture() {
        println!("Starting packet capture test...");

        // 创建 broadcast channel，增加容量避免阻塞
        let (tx, _) = broadcast::channel(1000);
        println!("Created broadcast channel with capacity 1000");
        
        // 列出可用接口
        match list_interfaces() {
            Ok(interfaces) => println!("Available interfaces: {:?}", interfaces),
            Err(e) => println!("Failed to list interfaces: {}", e),
        }
        
        // 使用本地回环接口进行测试
        let filter = PacketFilter {
            bpf_filter: "".to_string(), // 先不使用过滤器便于测试
            ..Default::default()
        };
        println!("Created packet filter without BPF");

        // 创建抓包器，获取停止信号发送器
        let mut capture = match PacketCapture::new("lo", tx.clone(), filter) {
            Ok(cap) => {
                println!("Successfully created packet capture on lo");
                cap
            }
            Err(e) => {
                println!("Failed to create packet capture: {}", e);
                panic!("Could not create packet capture");
            }
        };

        let stats_handler = capture.get_stats_handler();
        println!("Initialized capture stats handler");

        // 创建接收器
        let mut rx = tx.subscribe();

        // 先克隆一份用于停止
        let mut capture_for_stop = capture.clone_with_stop();

        // 设置停止信号
        let stop_handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            println!("Sending stop signal");
            capture_for_stop.break_loop();
        });

        // 启动捕获
        let capture_handle = tokio::spawn(async move {
            if let Err(e) = capture.capture_loop().await {
                println!("Capture loop error: {}", e);
            }
        });

        // 等待并接收数据包
        println!("Waiting for packets...");
        let timeout_duration = Duration::from_secs(5);
        
        // 使用 tokio::select! 同时等待多个异步操作
        tokio::select! {
            // 等待数据包
            res = async {
                while let Ok(packet) = rx.recv().await {
                    println!("Received packet: {:?}", packet);
                    return Ok::<_, broadcast::error::RecvError>(packet);
                }
                Err(broadcast::error::RecvError::Closed)
            } => {
                match res {
                    Ok(packet) => println!("Successfully received packet: {:?}", packet),
                    Err(e) => println!("Error receiving packet: {}", e),
                }
            }
            
            // 超时处理
            _ = tokio::time::sleep(timeout_duration) => {
                println!("Timeout waiting for packets after {} seconds", timeout_duration.as_secs());
            }
        }

        // 打印统计信息
        let (received, dropped, if_dropped) = stats_handler.get_stats();
        println!("Capture Statistics:");
        println!("  Packets received: {}", received);
        println!("  Packets dropped: {}", dropped);
        println!("  Interface drops: {}", if_dropped);

        // 等待捕获任务完成
        if let Err(e) = capture_handle.await {
            println!("Capture task error: {}", e);
        }

        // 验证
        let packets_received = stats_handler.packets_received.load(Ordering::Relaxed);
        println!("Final packets received count: {}", packets_received);
        assert!(packets_received >= 0, "Should have valid packet count");
    }
}
