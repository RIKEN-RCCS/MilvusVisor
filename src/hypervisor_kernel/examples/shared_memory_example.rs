// Example demonstrating the use of SharedMemory
//
// This example shows how to use the SharedMemory struct from the hypervisor_kernel crate.
// It creates a SharedMemory instance, writes data to it, reads it back, and verifies
// that the data was correctly stored.
//
// To run this example:
// 1. Build the example with: cargo build --example shared_memory_example
// 2. Run the example with: cargo run --example shared_memory_example

#![no_std]
#![no_main]

extern crate hypervisor_kernel;

use core::panic::PanicInfo;
use hypervisor_kernel::drivers::shared_memory::SharedMemory;
use core::sync::atomic::AtomicU32;

// Required for no_std crates
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// Entry point for the example
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Create a SharedMemory instance
    let mut shared_mem = SharedMemory {
        lock: AtomicU32::new(0),
        ready: AtomicU32::new(0),
        len: 0,
        data: [0; 1024 * 1024],
    };

    // Test data to write to shared memory
    let test_data = b"Hello, MilvusVisor!";
    
    // Write data to shared memory
    shared_mem.write(test_data);
    
    // Verify data was written correctly
    let is_ready = shared_mem.is_ready();
    
    // Read data from shared memory
    if let Some(read_data) = shared_mem.read() {
        // Verify read data matches written data
        let mut matches = true;
        for (i, &byte) in test_data.iter().enumerate() {
            if read_data[i] != byte {
                matches = false;
                break;
            }
        }
        
        // If data matches, clear the shared memory
        if matches {
            shared_mem.clear();
        }
    }
    
    // Loop forever (since we can't return from _start in no_std)
    loop {}
}