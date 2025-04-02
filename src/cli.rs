use config::ConfigError;
use serde::Deserialize;
use clap::Parser;
use std::{fs, net::Ipv4Addr};
use crate::error::Result;
use crate::error::ForwarderError;

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
    pub log_level: LoggingConfig,
}

impl Config {
    /// 从 YAML 文件加载配置
    pub fn from_file(path: &str) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&contents)?;
        Ok(config)
    }

    /// 验证配置是否有效
    pub fn validate(&self) -> Result<()> {
        // 增加更多验证
        self.validate_interface()?;
        self.validate_forwarder()?;
        Ok(())
    }

    fn validate_interface(&self) -> Result<()> {
        // 验证网络接口配置
        if self.interface.buffer_size < 1024 {
            return Err(ForwarderError::Config(
                "Buffer size must be at least 1024 bytes".to_string()
            ));
        }
        Ok(())
    }

    fn validate_forwarder(&self) -> Result<()> {
        // 验证转发器配置
        match self.forwarder.protocol.as_str() {
            "gre" | "vxlan" | "zmq" => Ok(()),
            _ => Err(ForwarderError::Config(
                "Unsupported protocol".to_string()
            ))
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ForwarderConfig {
    pub protocol: String,
    pub destination: String,
    pub port: Option<u16>,
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_config_validation() {
        let config = Config {
            forwarder: ForwarderConfig {
                protocol: "gre".to_string(),
                destination: "192.168.1.1".to_string(),
                port: Some(4789),
                max_packet_size: 1500,
                queue_size: 1000,
                bind_device: None,
            },
            interface: InterfaceConfig {
                name: "eth0".to_string(),
                promiscuous: true,
                buffer_size: 65535,
                client_ip: "192.168.1.2".parse().unwrap(),
            },
            log_level: LoggingConfig {
                level: "info".to_string(),
                file: None,
            },
        };
        
        assert!(config.validate().is_ok());
    }
}