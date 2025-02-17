// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Console with UEFI Output Protocol
//!

use uefi::{EfiStatus, output::EfiOutputProtocol};

use core::fmt;

pub struct Console<'a> {
    efi_output_protocol: &'a EfiOutputProtocol,
}

static mut DEFAULT_CONSOLE: Option<Console> = None;

impl<'a> Console<'a> {
    pub const fn new(efi_output_protocol: &'a EfiOutputProtocol) -> Self {
        Self {
            efi_output_protocol,
        }
    }
}

impl fmt::Write for Console<'_> {
    fn write_str(&mut self, string: &str) -> fmt::Result {
        if self.efi_output_protocol.output(string) == EfiStatus::EfiSuccess {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

pub fn init_default_console(efi_output_protocol: &'static EfiOutputProtocol) {
    unsafe { (&raw mut DEFAULT_CONSOLE).write(Some(Console::new(efi_output_protocol))) };
}

pub fn print(args: fmt::Arguments) {
    use fmt::Write;
    if let Some(Some(console)) = unsafe { (&raw mut DEFAULT_CONSOLE).as_mut() } {
        if console.write_fmt(args).is_err() {
            panic!("write_fmt was failed.");
        }
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
