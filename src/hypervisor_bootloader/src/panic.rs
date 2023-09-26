// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Panic Handler
//!

use common::cpu::halt_loop;

use core::panic;

#[panic_handler]
#[no_mangle]
pub fn panic(info: &panic::PanicInfo) -> ! {
    let location = info.location();
    let message = info.message();

    println!("\n\n---- panic ----");
    if location.is_some() && message.is_some() {
        println!(
            "Line {} in {}\nMessage: {}",
            location.unwrap().line(),
            location.unwrap().file(),
            message.unwrap()
        );
    }

    halt_loop()
}
