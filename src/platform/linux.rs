use super::interface::NetworkInterface;
use crate::error::ForwarderError;
use std::os::unix::io::AsRawFd;

pub struct LinuxInterface;

impl LinuxInterface {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkInterface for LinuxInterface {
    fn bind_to_interface(&self, socket: &socket2::Socket, interface_name: &str) -> crate::error::Result<()> {
        #[cfg(target_os = "linux")]
        unsafe {
            let fd = socket.as_raw_fd();
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                interface_name.as_ptr() as *const libc::c_void,
                interface_name.len() as u32,
            ) == 0
            {
                Ok(())
            } else {
                Err(ForwarderError::Interface("Failed to bind to interface".to_string()))
            }
        }
        #[cfg(not(target_os = "linux"))]
        Err(ForwarderError::Interface("Not implemented for this platform".to_string()))
    }

    fn get_available_interface(&self) -> crate::error::Result<Vec<String>> {
        // TODO: Implement using libc for Linux
        Ok(Vec::new())
    }

    fn get_interface_index(&self, _interface_name: &str) -> crate::error::Result<u32> {
        // TODO: Implement using libc for Linux
        Ok(0)
    }
}

