// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

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
