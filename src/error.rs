use futures::{future::Join, io};
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Error, Debug)]
pub enum ForwarderError {
    #[error("Interface error: {0}")]
    Interface(String),
    
    #[error("Packet capture error: {0}")]
    Capture(String),
    
    #[error("Protocol error: {0}")]
    Protocol(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("IO error {0}")]
    Io(io::ErrorKind),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid packet format: {0}")]
    PacketFormat(String),

    #[error("Buffer overflow: needed {needed} bytes but only had {available}")]
    BufferOverflow {
        needed: usize,
        available: usize,
    },

    #[error("Invalid checksum")]
    InvalidChecksum,

    #[error("Packet too large: {size} bytes (max: {max})")]
    PacketTooLarge {
        size: usize,
        max: usize,
    },

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Timeout after {0} seconds")]
    Timeout(u64),

    #[error("Connection error: {0}")]
    Connection(String),
    
    #[error("Resource not found: {0}")]
    NotFound(String),
    
    #[error("Operation not supported: {0}")]
    Unsupported(String),

    #[error("JoinError: {0}")]
    JoinError(JoinError),
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<pcap::Error> for ForwarderError {
    fn from(err: pcap::Error) -> Self {
        match err {
            pcap::Error::IoError(e) => Self::Io(e),
            pcap::Error::TimeoutExpired => Self::Timeout(0),
            _ => Self::Capture(err.to_string()),
        }
    }
}

impl From<io::Error> for ForwarderError {
    fn from(err: io::Error) -> Self {
        ForwarderError::Io(err.kind())
    }
}

impl From<JoinError> for ForwarderError {
    fn from(err: JoinError) -> Self {
        ForwarderError::JoinError(err)
    }
}

impl From<serde_yaml::Error> for ForwarderError {
    fn from(err: serde_yaml::Error) -> Self {
        ForwarderError::Config(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ForwarderError>;