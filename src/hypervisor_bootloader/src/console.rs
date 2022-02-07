//!
//! Console Input/Output Manager
//!
//! 主にUEFIコンソールの利用を想定
//!

use uefi::output::EfiOutputProtocol;
use uefi::EfiStatus;

use core::fmt;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

pub struct Console {
    uefi_output_console: MaybeUninit<&'static EfiOutputProtocol>,
    write_lock: AtomicBool,
}

pub static mut DEFAULT_CONSOLE: Console = Console::new();

impl Console {
    pub const fn new() -> Self {
        Self {
            uefi_output_console: MaybeUninit::uninit(),
            write_lock: AtomicBool::new(false),
        }
    }

    pub fn init(&mut self, efi_output_protocol: *const EfiOutputProtocol) {
        self.uefi_output_console = MaybeUninit::new(unsafe { &*efi_output_protocol });
    }

    fn acquire_write_lock(&self) {
        loop {
            if self
                .write_lock
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            while self.write_lock.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    fn release_write_lock(&self) {
        self.write_lock.store(false, Ordering::Release)
    }

    /// For panic_handler
    pub unsafe fn force_release_write_lock(&self) {
        self.release_write_lock();
    }
}

impl fmt::Write for Console {
    /// write_strはwrite_fmt内部で呼び出されます。
    fn write_str(&mut self, string: &str) -> fmt::Result {
        self.acquire_write_lock();
        let result = unsafe { self.uefi_output_console.assume_init().output(string) };
        self.release_write_lock();
        if result == EfiStatus::EfiSuccess {
            fmt::Result::Ok(())
        } else {
            fmt::Result::Err(fmt::Error)
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
    ($($arg:tt)*) => {
        $crate::console::print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    ($fmt:expr) => (print!(concat!($fmt,"\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!($fmt, "\n"),$($arg)*))
}
