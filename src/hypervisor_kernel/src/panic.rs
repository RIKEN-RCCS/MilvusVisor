// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Panic Handler
//!

use crate::serial_port::DEFAULT_SERIAL_PORT;

use common::cpu::halt_loop;

use core::panic;

#[panic_handler]
#[no_mangle]
pub fn panic(info: &panic::PanicInfo) -> ! {
    let location = info.location();
    let message = info.message();

    unsafe {
        DEFAULT_SERIAL_PORT
            .as_ref()
            .and_then(|f| Some(f.force_release_write_lock()))
    };
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
