use serde::Deserialize;
use clap::Parser;
use std::{fs, net::Ipv4Addr};
use crate::error::Result;

#[derive(Parser, Debug, Deserialize)]
#[command(author, version, about)]
pub struct Args {
    /// 配置文件路径
    #[arg(short, long)]
    pub config: Option<String>,

    /// 要监听的网络接口名称
    #[arg(short, long)]
    pub interface: Option<String>,

    /// 转发协议(gre/socket/zmq/vxlan)
    #[arg(short, long)]
    pub protocol: Option<String>,

    /// 目标地址
    #[arg(short, long)]
    pub destination: Option<String>,
    
    /// 日志级别
    #[arg(short, long, default_value = "info")]
    pub log_level: String,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    /// 要监听的网络接口名称
    pub interface: InterfaceConfig,
    
    pub forwarder: ForwarderConfig,
    /// 日志级别
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

// 默认日志级别
fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    /// 从 YAML 文件加载配置
    pub fn from_file(path: &str) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ForwarderConfig {
    pub protocol: String,
    pub destination: String,
    pub port: u16,
    pub max_packet_size: usize,
    pub queue_size: usize,
    pub bind_device: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InterfaceConfig {
    pub name: String,
    pub promiscuous: bool,
    pub buffer_size: usize,
    pub client_ip: Ipv4Addr,
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
}