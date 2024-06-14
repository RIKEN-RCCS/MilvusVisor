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
    println!("\n\nBoot Loader Panic: {}", info);
    common::cpu::halt_loop()
}
