
use super::interface::NetworkInterface;
pub struct LinuxInterface;

use nix::setsockopt;

impl LinuxInterface {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkInterface for LinuxInterface {
    
    fn bind_to_interface(&self, socket: socket2::Socket, interface_name: &str) -> crate::error::Result<()> {
        setsockopt(s, level, optname, optval, optlen)
    }

    fn get_available_interface(&self) -> crate::error::Result<Vec<String>> {
        
    }

    fn get_interface_index(&self, interface_name: &str) -> crate::error::Result<u32> {
        
    }
}

