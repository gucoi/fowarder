use crate::error::ForwarderError;

use super::interface::NetworkInterface;
use std::os::windows::io::AsRawSocket;
use windows::Win32::Networking::WinSock::*;
use windows::Win32::NetworkManagement::IpHelper;
use windows::core::PWSTR;

pub struct WindowsInterface;

impl WindowsInterface {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkInterface for WindowsInterface {
    fn bind_to_interface(&self, sock: socket2::Socket, interface_name: &str) -> crate::error::Result<()> {
        let index = self.get_interface_index(interface_name)?;
        let raw_socket = sock.as_raw_socket();
        unsafe {
            let index_net = u32::to_be(index);
            let result = setsockopt(
                SOCKET(raw_socket as usize),  // 转换为 SOCKET 类型
                IPPROTO_IP.0,
                IP_UNICAST_IF as i32,
                Some(&index_net.to_ne_bytes()),  // 正确的类型转换
            );
            if result == 0 {
                Ok(())
            } else {
                Err(ForwarderError::Interface("Failed to bind to interface".to_string()))
            }
        }
    }

    fn get_available_interface(&self) -> crate::error::Result<Vec<String>> {
        // 使用 Windows API 获取网络接口列表
        unsafe {
            let mut buf_len = 0u32;
            IpHelper::GetAdaptersAddresses(
                0,
                IpHelper::GET_ADAPTERS_ADDRESSES_FLAGS(0),
                None,
                None,
                &mut buf_len,
            );
            
            let mut buf = vec![0u8; buf_len as usize];
            let result = IpHelper::GetAdaptersAddresses(
                0,
                IpHelper::GET_ADAPTERS_ADDRESSES_FLAGS(0),
                None,
                None,
                &mut buf_len,
            );
            
            if result > 0 {
                let mut adapter = buf.as_ptr() as *const IpHelper::IP_ADAPTER_ADDRESSES_LH;
                let mut interfaces = Vec::new();
                
                while !adapter.is_null() {
                    let friendly_name = unsafe {
                        std::slice::from_raw_parts(
                            (*adapter).FriendlyName.0,
                            (*adapter).FriendlyName.len() as usize,
                        )
                    };
                    if let Ok(name) = String::from_utf16(friendly_name) {
                        interfaces.push(name);
                    }
                    adapter = (*adapter).Next;
                }
                
                Ok(interfaces)
            } else {
                Err(ForwarderError::Interface("Failed to get adapters addresses".to_string()))
            }
        }
    }

    fn get_interface_index(&self, interface_name: &str) -> crate::error::Result<u32> {
        
        let mut index = 0u32;
        let wide_name: Vec<u16> = interface_name.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            IpHelper::GetAdapterIndex(
                PWSTR(wide_name.as_ptr() as *mut _),
                &mut index,
            );
        }
        Ok(index)
    }

}
