use pnet::datalink::{self, NetworkInterface};
use crate::error::{Result, ForwarderError};

pub struct InterfaceManager {
    interface: NetworkInterface,
}

impl InterfaceManager {
    pub fn new(name: &str) -> Result<Self> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
            .ok_or_else(|| ForwarderError::Interface(format!("Interface {} not found", name)))?;
            
        Ok(Self { interface })
    }
    
    pub fn get_interface(&self) -> &NetworkInterface {
        &self.interface
    }
    
    pub fn set_promiscuous(&self, enable: bool) -> Result<()> {
        // TODO: 实现接口混杂模式设置
        Ok(())
    }
}