// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use super::SerialPortDevice;

use core::ptr;

const UART_STATUS: usize = 0x02c;
const UART_FIFO: usize = 0x030;

const UART_STATUS_FULL: u32 = 1 << 4;

pub struct SerialXilinxUart {
    base_address: usize,
}

impl SerialPortDevice for SerialXilinxUart {
    fn new(address: usize) -> Self {
        Self {
            base_address: address,
        }
    }

    fn write_char(&mut self, c: u8) -> Result<(), ()> {
        unsafe { ptr::write_volatile((self.base_address + UART_FIFO) as *mut u32, c as u32) };
        Ok(())
    }

    fn is_write_fifo_full(&self) -> bool {
        (unsafe { ptr::read_volatile((self.base_address + UART_STATUS) as *const u32) }
            & UART_STATUS_FULL)
            != 0
    }
}
