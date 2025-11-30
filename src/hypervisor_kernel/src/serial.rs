use common::HYPERVISOR_SERIAL_BASE_ADDRESS;
use core::ptr;

pub const UART_RSR_OFFSET: usize = 0x004;
pub const UART_FR_OFFSET: usize = 0x018;
pub const UART_ILPR_OFFSET: usize = 0x020;
pub const UART_IBRD_OFFSET: usize = 0x024;
pub const UART_FBRD_OFFSET: usize = 0x028;
pub const UART_LCRH_OFFSET: usize = 0x02C;
pub const UART_CR_OFFSET: usize = 0x030;
pub const UART_IFLS_OFFSET: usize = 0x034;
pub const UART_IMSC_OFFSET: usize = 0x038;
pub const UART_RIS_OFFSET: usize = 0x03C;
pub const UART_DMACR_OFFSET: usize = 0x048;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SerialState {
    pub rsr: u8,
    pub ibrd: u16,
    pub fbrd: u8,
    pub lcr_h: u8,
    pub cr: u16,
    pub ifls: u8,
    pub imsc: u16,
    pub ris: u16,
    pub dmacr: u8,
    pub ilpr: u8,
}

impl SerialState {
    /// Capture the current PL011 register state.
    pub unsafe fn read_from_hardware() -> Self {
        Self {
            rsr: read_serial_register(UART_RSR_OFFSET),
            ibrd: read_serial_register(UART_IBRD_OFFSET),
            fbrd: read_serial_register(UART_FBRD_OFFSET),
            lcr_h: read_serial_register(UART_LCRH_OFFSET),
            cr: read_serial_register(UART_CR_OFFSET),
            ifls: read_serial_register(UART_IFLS_OFFSET),
            imsc: read_serial_register(UART_IMSC_OFFSET),
            ris: read_serial_register(UART_RIS_OFFSET),
            dmacr: read_serial_register(UART_DMACR_OFFSET),
            ilpr: read_serial_register(UART_ILPR_OFFSET),
        }
    }

    /// Print the captured state for debugging.
    pub fn dump(&self, label: &str) {
        println!("Serial State [{label}]");
        println!("  ILPR: {:#X}", self.ilpr);
        println!("  IBRD: {:#X}", self.ibrd);
        println!("  FBRD: {:#X}", self.fbrd);
        println!("  LCR_H: {:#X}", self.lcr_h);
        println!("  CR: {:#X} ({:#b})", self.cr, self.cr);
        println!("  IFLS: {:#X}", self.ifls);
        println!("  IMSC: {:#X} ({:#b})", self.imsc, self.imsc);
        println!("  RIS: {:#X}", self.ris);
        println!("  DMACR: {:#X}", self.dmacr);
        println!("  RSR: {:#X}", self.rsr);
    }
}

#[inline(always)]
pub unsafe fn read_serial_register<T>(offset: usize) -> T {
    ptr::read_volatile((HYPERVISOR_SERIAL_BASE_ADDRESS + offset) as *const T)
}

#[inline(always)]
pub unsafe fn write_serial_u32(offset: usize, value: u32) {
    ptr::write_volatile((HYPERVISOR_SERIAL_BASE_ADDRESS + offset) as *mut u32, value);
}

/// Capture and print the current hardware state immediately.
pub fn dump_live_serial_state(label: &str) {
    unsafe {
        let state = SerialState::read_from_hardware();
        state.dump(label);
        let fr: u16 = read_serial_register(UART_FR_OFFSET);
        println!("  FR: {:#X} ({:#b})", fr, fr);
    }
}
