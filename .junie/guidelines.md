# MilvusVisor Development Guidelines

This document provides guidelines and information for developers working on the MilvusVisor project.

## Build/Configuration Instructions

### Building the Project

MilvusVisor uses a custom build system based on Cargo's workspace feature and a custom `xtask` command.

#### Basic Build

```bash
cd src
cargo xtask build
```

#### Build with Specific Features

MilvusVisor supports various features that can be enabled during build:

```bash
cd src
cargo xtask build -f feature1,feature2,...
```

Available features include:
- `i210` - Protect Intel I210 EEPROM from writing access
- `mt27800` - Protect Mellanox Technologies MT27800 from firmware update
- `smmu` - Use SMMUv3 Stage 2 Page Translation to protect from DMA attack
- `fast_restore` - Fast restoring the guest environments without rebooting
- `acpi_table_protection` - Protect ACPI Tables from write accesses
- `advanced_memory_manager` - Use linked-list style memory allocator
- `contiguous_bit` - Set contiguous bit enabled if available
- `a64fx` - A64FX specific registers' initialization
- `tftp` - Download hypervisor_kernel and payload via TFTP
- `raspberrypi` - For running MilvusVisor on a Raspberry Pi 4
- `virtio_net` - Add virtual devices to communicate with OS
- `embed_kernel` - Embed the hypervisor kernel into the bootloader

To build with default features plus additional ones:

```bash
cd src
cargo xtask build -f default,feature1,feature2,...
```

#### Building with Docker

If you prefer to use Docker for building:

```bash
cd src
./build_by_docker.sh
```

You can pass additional arguments to the build script:

```bash
cd src
./build_by_docker.sh -f default,feature1,feature2,...
```

### Running the Hypervisor

#### On QEMU

```bash
cd src
cargo xtask run --bios /path/to/QEMU_EFI.fd
```

Additional options:
- `--smp <num>` - Specify number of cores
- `--memory <size>` - Specify memory size
- `--mount-directory <path>` - Mount a directory
- `--debug` - Enable debug mode

#### On Physical Hardware

1. Build the hypervisor
2. Identify the EFI partition on your USB drive (e.g., `/dev/sdX1`)
3. Write the hypervisor to the USB drive:
   ```bash
   sudo cargo xtask write -d /dev/sdX1
   ```
4. Boot the target machine from the USB drive

## Testing Information

### Testing Approach

MilvusVisor is a bare-metal hypervisor that runs without an operating system, which makes traditional testing challenging. Testing is primarily done through:

1. **Example Programs**: Examples that demonstrate specific functionality
2. **Manual Testing**: Running on target hardware and verifying behavior
3. **QEMU Testing**: Testing in QEMU before deploying to hardware

### Creating and Running Examples

Examples are located in the `examples` directory of each crate. To create a new example:

1. Create a new file in the appropriate `examples` directory
2. Implement the example using the no_std environment
3. Include necessary panic handlers and entry points

For example, to test the SharedMemory module:

```rust
// src/hypervisor_kernel/examples/shared_memory_example.rs
#![no_std]
#![no_main]

extern crate hypervisor_kernel;

use core::panic::PanicInfo;
use hypervisor_kernel::drivers::shared_memory::SharedMemory;
use core::sync::atomic::AtomicU32;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

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
```

### Testing on Hardware

When testing on hardware, follow these steps:

1. Build the hypervisor with the features you want to test
2. Deploy to the target hardware using the appropriate method
3. Document the test results, including:
   - Hardware configuration
   - Enabled features
   - Observed behavior
   - Any issues encountered

## Additional Development Information

### Code Style

- Follow Rust's standard code style and idioms
- Use `rustfmt` to format code
- Use `clippy` to catch common mistakes and improve code quality

### Project Structure

- `src/hypervisor_bootloader` - UEFI bootloader that loads the hypervisor kernel
- `src/hypervisor_kernel` - The main hypervisor kernel
- `src/common` - Common code shared between components
- `src/uefi` - UEFI-related functionality
- `src/xtask` - Custom build scripts and utilities

### Memory Management

- The hypervisor uses a custom memory management system
- Memory is allocated during initialization and managed carefully
- Dynamic allocation is limited to avoid fragmentation

### Debugging

- Use QEMU for initial debugging
- Enable debug output with the `--debug` flag
- Hardware debugging requires specialized equipment (JTAG, etc.)

### Documentation

Generate documentation for each crate:

```bash
cd src/hypervisor_bootloader
cargo doc --open

cd src/hypervisor_kernel
cargo doc --open
```

### Contributing

When contributing to MilvusVisor:

1. Follow the guidelines in CONTRIBUTING.md
2. Test your changes on at least one hardware platform
3. Document any new features or changes
4. Ensure backward compatibility when possible