use super::SerialPortDevice;

use core::ptr;

const UART_WR_FIFO: usize = 0x000;
const UART_STATUS: usize = 0x00c;

pub struct SerialMesonGxUart {
    base_address: usize,
}

impl SerialPortDevice for SerialMesonGxUart {
    fn new(address: usize) -> Self {
        Self {
            base_address: address,
        }
    }

    fn write_char(&mut self, c: u8) -> Result<(), ()> {
        unsafe { ptr::write_volatile((self.base_address + UART_WR_FIFO) as *mut u32, c as u32) };
        return Ok(());
    }

    fn is_write_fifo_full(&self) -> bool {
        (unsafe { ptr::read_volatile((self.base_address + UART_STATUS) as *const u32) } & (1 << 21))
            != 0
    }
}
