// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Console with UEFI Output Protocol
//!

//use common::spin_flag::SpinLockFlag;

use uefi::{output::EfiOutputProtocol, EfiStatus};

use core::fmt;
use core::mem::MaybeUninit;

pub struct Console {
    uefi_output_console: MaybeUninit<&'static EfiOutputProtocol>,
    //write_lock: SpinLockFlag, // Currently, Bootloader runs only BSP. Therefore the lock is not necessary.
}

pub static mut DEFAULT_CONSOLE: Console = Console::new();

impl Console {
    pub const fn new() -> Self {
        Self {
            uefi_output_console: MaybeUninit::uninit(),
            //write_lock: SpinLockFlag::new(),
        }
    }

    pub fn init(&mut self, efi_output_protocol: *const EfiOutputProtocol) {
        self.uefi_output_console = MaybeUninit::new(unsafe { &*efi_output_protocol });
    }

    /// For panic_handler
    pub unsafe fn force_release_write_lock(&self) {
        //self.write_lock.unlock();
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, string: &str) -> fmt::Result {
        //self.write_lock.lock();
        let result = unsafe { self.uefi_output_console.assume_init().output(string) };
        //self.write_lock.unlock();
        if result == EfiStatus::EfiSuccess {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

pub fn print(args: fmt::Arguments) {
    use fmt::Write;
    let result = unsafe { DEFAULT_CONSOLE.write_fmt(args) };
    if result.is_err() {
        panic!("write_fmt was failed.");
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::console::print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    ($fmt:expr) => ($crate::console::print(format_args!("{}\n", format_args!($fmt))));
    ($fmt:expr, $($arg:tt)*) => ($crate::console::print(format_args!("{}\n", format_args!($fmt, $($arg)*))));
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
