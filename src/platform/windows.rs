use super::interface::NetworkInterface;

pub struct WindowsInterface;

impl WindowsInterface {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkInterface for WindowsInterface {
    fn bind_to_interface(&self, socket: socket2::Socket, interface_name: &str) -> crate::error::Result<()> {
       let index = self.get_interface_index(interface_name)?;
        // 在 Windows 上，我们使用 IP_UNICAST_IF 选项来绑定接口
        let raw_socket = socket.as_raw_socket();
        unsafe {
            use windows::Win32::Networking::WinSock::{
                setsockopt,
                IPPROTO_IP,
                IP_UNICAST_IF,
            };
            let index_net = u32::to_be(index);
            let result = setsockopt(
                raw_socket as _,
                IPPROTO_IP as i32,
                IP_UNICAST_IF as i32,
                &index_net as *const u32 as *const i8,
                std::mem::size_of::<u32>() as i32,
            );
            if result == 0 {
                Ok(())
            } else {
                Err(anyhow!("Failed to bind to interface"))
            }
        } 
    }

    fn get_available_interface(&self) -> crate::error::Result<Vec<String>> {
        // 使用 Windows API 获取网络接口列表
        unsafe {
            let mut buf_len = 0u32;
            IpHelper::GetAdaptersAddresses(
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut buf_len,
            );
            
            let mut buf = vec![0u8; buf_len as usize];
            let result = IpHelper::GetAdaptersAddresses(
                0,
                0,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut _,
                &mut buf_len,
            );
            
            if result.is_ok() {
                let mut adapter = buf.as_ptr() as *const IpHelper::IP_ADAPTER_ADDRESSES_LH;
                let mut interfaces = Vec::new();
                
                while !adapter.is_null() {
                    let friendly_name = unsafe {
                        std::slice::from_raw_parts(
                            (*adapter).FriendlyName.0,
                            (*adapter).FriendlyName.1 as usize,
                        )
                    };
                    if let Ok(name) = String::from_utf16(friendly_name) {
                        interfaces.push(name);
                    }
                    adapter = (*adapter).Next;
                }
                
                Ok(interfaces)
            } else {
                Err(anyhow!("Failed to get adapters addresses"))
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
            )
            .map_err(|e| anyhow!("Failed to get interface index: {:?}", e))?;
        }
        Ok(index)
    }

}
