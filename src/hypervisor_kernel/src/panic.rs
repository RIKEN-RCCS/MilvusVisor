// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Panic Handler
//!

#[panic_handler]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    unsafe { crate::drivers::serial_port::force_release_serial_port_lock() };
    println!("\n\n=====Hypervisor Panic=====");
    if let Some(location) = info.location() {
        println!(
            "{}:{}:{}: {}",
            location.file(),
            location.line(),
            location.column(),
            info.message()
        );
    } else {
        println!("{}", info.message());
    }
    println!("===== Dump complete =====");
    common::cpu::halt_loop()
}
