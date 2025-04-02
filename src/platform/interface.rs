use socket2::Socket;

use crate::error::Result;
use crate::platform::windows::WindowsInterface;

pub trait NetworkInterface: Send + Sync {
    fn bind_to_interface(&self, sock: &Socket, interface_name: &str) -> Result<()>;
    fn get_interface_index(&self, interface_name: &str) -> Result<u32>;
    fn get_available_interface(&self) -> Result<Vec<String>>;
}

pub fn create_interface() -> Box<dyn NetworkInterface> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxInterface::new())
    }
    #[cfg(windows)]
    {
        Box::new(WindowsInterface::new())
    }
}