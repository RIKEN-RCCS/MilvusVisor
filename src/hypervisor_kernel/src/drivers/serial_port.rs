// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use core::fmt;

use arm_pl011::SerialArmPl011;
use arm_sbsa_generic_uart::SerialSbsaUart;
use common::serial_port::{SerialPortInfo, SerialPortType};
use common::spin_flag::SpinLockFlag;
use meson_gx_uart::SerialMesonGxUart;

mod arm_pl011;
mod arm_sbsa_generic_uart;
mod meson_gx_uart;

trait SerialPortDevice {
    fn new(address: usize) -> Self;
    fn write_char(&mut self, c: u8) -> Result<(), ()>;
    fn is_write_fifo_full(&self) -> bool;
}

enum Device {
    ArmPl011(SerialArmPl011),
    ArmSbsaGenericUart(SerialSbsaUart),
    MesonGxUart(SerialMesonGxUart),
}

impl SerialPortDevice for Device {
    fn new(_: usize) -> Self {
        unreachable!()
    }

    fn write_char(&mut self, c: u8) -> Result<(), ()> {
        match self {
            Device::ArmPl011(d) => d.write_char(c),
            Device::ArmSbsaGenericUart(d) => d.write_char(c),
            Device::MesonGxUart(d) => d.write_char(c),
        }
    }

    fn is_write_fifo_full(&self) -> bool {
        match self {
            Device::ArmPl011(d) => d.is_write_fifo_full(),
            Device::ArmSbsaGenericUart(d) => d.is_write_fifo_full(),
            Device::MesonGxUart(d) => d.is_write_fifo_full(),
        }
    }
}

pub struct SerialPort {
    device: Device,
    write_lock: SpinLockFlag,
}

impl SerialPort {
    pub fn new(info: SerialPortInfo) -> Self {
        Self {
            device: match info.port_type {
                SerialPortType::ArmPl011 => {
                    Device::ArmPl011(SerialArmPl011::new(info.virtual_address))
                }
                SerialPortType::ArmSbsaGenericUart => {
                    Device::ArmSbsaGenericUart(SerialSbsaUart::new(info.virtual_address))
                }
                SerialPortType::MesonGxUart => {
                    Device::MesonGxUart(SerialMesonGxUart::new(info.virtual_address))
                }
            },
            write_lock: SpinLockFlag::new(),
        }
    }

    fn wait_fifo(&mut self) -> fmt::Result {
        assert!(self.write_lock.is_locked());
        let mut timeout = 0xFFFFusize;
        while self.device.is_write_fifo_full() {
            timeout -= 1;
            if timeout == 0 {
                self.write_lock.unlock();
                return Err(fmt::Error);
            }
            core::hint::spin_loop();
        }
        return Ok(());
    }

    /// For panic_handler
    pub unsafe fn force_release_write_lock(&self) {
        self.write_lock.unlock();
    }
}

pub unsafe fn init_default_serial_port(info: SerialPortInfo) {
    DEFAULT_SERIAL_PORT = Some(SerialPort::new(info));
}

pub unsafe fn force_release_serial_port_lock() {
    if let Some(e) = &mut *core::ptr::addr_of_mut!(DEFAULT_SERIAL_PORT) {
        e.force_release_write_lock();
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_lock.lock();
        for c in s.as_bytes() {
            self.wait_fifo()?;
            if *c == b'\n' {
                let result = self.device.write_char(b'\r');
                if result.is_err() {
                    self.write_lock.unlock();
                    return Err(fmt::Error);
                }
                self.wait_fifo()?;
            }
            if self.device.write_char(*c).is_err() {
                self.write_lock.unlock();
                return Err(fmt::Error);
            }
        }
        self.write_lock.unlock();
        return Ok(());
    }
}

static mut DEFAULT_SERIAL_PORT: Option<SerialPort> = None;

pub fn print(args: fmt::Arguments) {
    if let Some(s) = unsafe { &mut *core::ptr::addr_of_mut!(DEFAULT_SERIAL_PORT) } {
        use fmt::Write;
        let _ = s.write_fmt(args);
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::drivers::serial_port::print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    ($fmt:expr) => ($crate::drivers::serial_port::print(format_args!("{}\n", format_args!($fmt))));
    ($fmt:expr, $($arg:tt)*) => ($crate::drivers::serial_port::print(format_args!("{}\n", format_args!($fmt, $($arg)*))));
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! pr_debug {
    ($fmt:expr) => (println!($fmt));
    ($fmt:expr, $($arg:tt)*) => (println!($fmt, $($arg)*));
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! pr_debug {
    ($fmt:expr) => {};
    ($fmt:expr, $($arg:tt)*) => {};
}
