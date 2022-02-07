mod arm_pl011;
mod arm_sbsa_generic_uart;
mod meson_gx_uart;

use arm_pl011::SerialArmPl011;
use arm_sbsa_generic_uart::SerialSbsaUart;
use meson_gx_uart::SerialMesonGxUart;

use common::serial_port::{SerialPortInfo, SerialPortType};

use core::fmt;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

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
    write_lock: AtomicBool,
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
            write_lock: AtomicBool::new(false),
        }
    }

    fn acquire_write_lock(&self) {
        loop {
            if self
                .write_lock
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            while self.write_lock.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    fn release_write_lock(&self) {
        self.write_lock.store(false, Ordering::Release)
    }

    fn wait_fifo(&mut self) -> core::fmt::Result {
        let mut timeout = 0xFFFFusize;
        while self.device.is_write_fifo_full() {
            timeout -= 1;
            if timeout == 0 {
                self.release_write_lock();
                return Err(core::fmt::Error);
            }
            core::hint::spin_loop();
        }
        return Ok(());
    }

    /// For panic_handler
    pub unsafe fn force_release_write_lock(&self) {
        self.release_write_lock();
    }
}

pub unsafe fn init_default_serial_port(info: SerialPortInfo) {
    DEFAULT_SERIAL_PORT = Some(SerialPort::new(info));
}

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.acquire_write_lock();
        for c in s.as_bytes() {
            self.wait_fifo()?;
            if *c == b'\n' {
                let result = self.device.write_char(b'\r');
                if result.is_err() {
                    self.release_write_lock();
                    return Err(fmt::Error);
                }
                self.wait_fifo()?;
            }
            if let Err(_) = self.device.write_char(*c) {
                self.release_write_lock();
                return Err(fmt::Error);
            }
        }
        self.release_write_lock();
        return Ok(());
    }
}

pub(super) static mut DEFAULT_SERIAL_PORT: Option<SerialPort> = None;

pub fn print(args: fmt::Arguments) {
    if let Some(s) = unsafe { &mut DEFAULT_SERIAL_PORT } {
        let _ = s.write_fmt(args);
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::serial_port::print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    ($fmt:expr) => (print!(concat!($fmt,"\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!($fmt, "\n"),$($arg)*))
}
