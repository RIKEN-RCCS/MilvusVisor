// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Panic Handler
//!

use core::panic;

use common::cpu::halt_loop;

#[panic_handler]
#[no_mangle]
pub fn panic(info: &panic::PanicInfo) -> ! {
    let location = info.location();
    let message = info.message();

    unsafe { crate::drivers::serial_port::force_release_serial_port_lock() };
    println!("\n\n=====Hypervisor Panic=====");
    println!(
        "Line {} in {}: {}",
        location.and_then(|l| Some(l.line())).unwrap_or(0),
        location.and_then(|l| Some(l.file())).unwrap_or("???"),
        message.unwrap_or(&format_args!("???"))
    );

    println!("===== Dump complete =====");
    halt_loop()
}
