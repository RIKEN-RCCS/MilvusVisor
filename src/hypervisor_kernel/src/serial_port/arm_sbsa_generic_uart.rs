use super::SerialPortDevice;

use core::ptr;

const UART_DR: usize = 0x000;
const UART_FR: usize = 0x018;

pub struct SerialSbsaUart {
    base_address: usize,
}

impl SerialPortDevice for SerialSbsaUart {
    fn new(address: usize) -> Self {
        Self {
            base_address: address,
        }
    }

    fn write_char(&mut self, c: u8) -> Result<(), ()> {
        unsafe { ptr::write_volatile((self.base_address + UART_DR) as *mut u8, c) };
        return Ok(());
    }

    fn is_write_fifo_full(&self) -> bool {
        (unsafe { ptr::read_volatile((self.base_address + UART_FR) as *const u16) } & (1 << 5)) != 0
    }
}
