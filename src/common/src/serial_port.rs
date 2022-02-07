//!
//! Serial Port
//!

#[derive(Clone)]
pub enum SerialPortType {
    ArmPl011,
    ArmSbsaGenericUart,
    MesonGxUart,
}

#[derive(Clone)]
pub struct SerialPortInfo {
    pub physical_address: usize,
    pub virtual_address: usize,
    pub port_type: SerialPortType,
}
