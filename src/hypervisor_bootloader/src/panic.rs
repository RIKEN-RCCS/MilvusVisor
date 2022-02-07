//!
//! Panic Handler
//!

use crate::console::DEFAULT_CONSOLE;

use core::panic;

#[panic_handler]
#[no_mangle]
pub fn panic(info: &panic::PanicInfo) -> ! {
    let location = info.location();
    let message = info.message();

    unsafe { DEFAULT_CONSOLE.force_release_write_lock() };
    println!("\n\n---- panic ----");
    if location.is_some() && message.is_some() {
        println!(
            "Line {} in {}\nMessage: {}",
            location.unwrap().line(),
            location.unwrap().file(),
            message.unwrap()
        );
    }

    loop {
        unsafe { asm!("wfi") }
    }
}
