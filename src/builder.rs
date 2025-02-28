#!/usr/bin/env -S cargo -q -Zscript

// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use std::env::Args;
use std::process::{exit, Command};

fn main() {
    // default settings
    let mut cargo_path = "cargo".to_string();

    let mut args = std::env::args();

    // Skip build script binary path
    let _ = args.next().unwrap();

    // Parse global option
    let mut command: String = "".to_string();
    while let Some(v) = args.next() {
        if !v.starts_with('-') {
            command = v;
            break;
        }
        if v == "-m" || v == "--manager" {
            let Some(manager) = args.next() else {
                eprintln!("Missing the manager path");
                show_help();
                return;
            };
            cargo_path = manager;
        }
        if v == "-h" || v == "--help" {
            show_help();
            exit(0);
        }
    }
    if command.is_empty() {
        eprintln!("Command is not specified.");
        show_help();
        exit(1);
    }

    match command.as_str() {
        "build" => build(args, &cargo_path),
        "run" => run(args),
        "write" => write_bin(args),
        "help" => show_help(),
        _ => {
            eprintln!("Invalid command");
            show_help();
            exit(1);
        }
    }
}

macro_rules! try_get_argument {
    ($args:expr, $target:expr, $error_message:expr, $error_code:expr) => {
        if let Some(a) = $args.next() {
            $target = a;
        } else {
            eprintln!($error_message);
            show_help();
            exit($error_code);
        }
    };
}

fn build(mut args: Args, cargo_path: &String) {
    // default settings
    let mut is_parallel = false;
    let mut is_release = false;
    let mut is_kernel_embedded = false;
    let mut cargo_args: Vec<String> = vec!["build".to_string()];
    let mut output_directory = "bin/EFI/BOOT".to_string();
    let hypervisor_bootloader_name = "hypervisor_bootloader";
    let hypervisor_kernel_name = "hypervisor_kernel";
    let hypervisor_bootloader_suffix = ".efi";
    let hypervisor_bootloader_output_name = "BOOTAA64.EFI";
    let hypervisor_bootloader_triple = "aarch64-unknown-uefi";
    let hypervisor_kernel_triple = "aarch64-unknown-none";

    // Parse options
    while let Some(v) = args.next() {
        if v == "-f" || v == "--features" {
            cargo_args.push("--no-default-features".to_string());
            cargo_args.push("--features".to_string());
            let f;
            try_get_argument!(args, f, "Failed to get features", 1);
            if f.contains("embed_kernel") {
                is_kernel_embedded = true;
            }
            cargo_args.push(f);
        } else if v == "-p" || v == "--parallel" {
            is_parallel = true;
        } else if v == "-r" || v == "--release" {
            is_release = true;
            cargo_args.push("--release".to_string());
        } else if v == "-o" || v == "--output-dir" {
            try_get_argument!(
                args,
                output_directory,
                "Failed to get the output directory",
                1
            );
        }
    }
    let mut bootloader_command = Command::new(cargo_path);
    let mut kernel_command = Command::new(cargo_path);

    // Set working directory
    let mut bootloader_path = std::env::current_dir().unwrap();
    let mut kernel_path = std::env::current_dir().unwrap();
    bootloader_path.push(hypervisor_bootloader_name);
    kernel_path.push(hypervisor_kernel_name);
    bootloader_command.current_dir(bootloader_path);
    kernel_command.current_dir(kernel_path);

    // Set arguments
    bootloader_command.args(cargo_args.clone());
    kernel_command.args(cargo_args);

    if is_kernel_embedded && is_parallel {
        is_parallel = false;
        eprintln!("Parallel build is disabled by \"embed_kernel\"");
    }

    if is_parallel {
        let mut bootloader_child = bootloader_command
            .spawn()
            .expect("Failed to run bootloader build");
        let mut kernel_child = kernel_command.spawn().expect("Failed to run kernel build");

        let bootloader_result = bootloader_child.wait();
        let kernel_result = kernel_child.wait();

        if bootloader_result.is_err() || kernel_result.is_err() {
            exit(1);
        }
        let bootloader_result = bootloader_result.unwrap();
        let kernel_result = kernel_result.unwrap();
        if !bootloader_result.success() {
            exit(bootloader_result.code().unwrap_or(1));
        }
        if !kernel_result.success() {
            exit(kernel_result.code().unwrap_or(1));
        }
    } else {
        if !is_kernel_embedded {
            let bootloader_result = bootloader_command
                .spawn()
                .expect("Failed to run bootloader build")
                .wait();
            if bootloader_result.is_err() {
                exit(1);
            }
            let bootloader_result = bootloader_result.unwrap();
            if !bootloader_result.success() {
                exit(bootloader_result.code().unwrap_or(1));
            }
        }

        let kernel_result = kernel_command
            .spawn()
            .expect("Failed to run kernel build")
            .wait();
        if kernel_result.is_err() {
            exit(1);
        }
        let kernel_result = kernel_result.unwrap();
        if !kernel_result.success() {
            exit(kernel_result.code().unwrap_or(1));
        }
    }

    // Move binaries
    let mut hypervisor_bootloader_binary_path = std::env::current_dir().unwrap();
    let mut hypervisor_kernel_binary_path = std::env::current_dir().unwrap();
    let mut bin_dir_path = std::env::current_dir().unwrap();
    bin_dir_path.push(output_directory);
    let mut hypervisor_bootloader_new_name = bin_dir_path.clone();
    let mut hypervisor_kernel_new_name = bin_dir_path.clone();

    hypervisor_bootloader_binary_path.push("target");
    hypervisor_bootloader_binary_path.push(hypervisor_bootloader_triple);
    hypervisor_kernel_binary_path.push("target");
    hypervisor_kernel_binary_path.push(hypervisor_kernel_triple);

    if is_release {
        hypervisor_bootloader_binary_path.push("release");
        hypervisor_kernel_binary_path.push("release");
    } else {
        hypervisor_bootloader_binary_path.push("debug");
        hypervisor_kernel_binary_path.push("debug");
    }
    hypervisor_bootloader_binary_path
        .push(hypervisor_bootloader_name.to_string() + hypervisor_bootloader_suffix);
    hypervisor_kernel_binary_path.push(hypervisor_kernel_name);

    // Build bootloader if kernel should be embedded
    if is_kernel_embedded {
        unsafe { std::env::set_var("HYPERVISOR_PATH", hypervisor_kernel_binary_path.clone()) };
        let bootloader_result = bootloader_command
            .spawn()
            .expect("Failed to run bootloader build")
            .wait();
        if bootloader_result.is_err() {
            exit(1);
        }
        let bootloader_result = bootloader_result.unwrap();
        if !bootloader_result.success() {
            exit(bootloader_result.code().unwrap_or(1));
        }
    }

    // Create bin directory
    std::fs::create_dir_all(bin_dir_path).expect("Failed to create output directory");

    // Move
    hypervisor_bootloader_new_name.push(hypervisor_bootloader_output_name);
    hypervisor_kernel_new_name.push(hypervisor_kernel_name);
    std::fs::rename(
        hypervisor_bootloader_binary_path,
        hypervisor_bootloader_new_name,
    )
    .expect("Failed to move hypervisor bootloader");
    std::fs::rename(hypervisor_kernel_binary_path, hypervisor_kernel_new_name)
        .expect("Failed to move hypervisor kernel");
}

fn run(mut args: Args) {
    // default settings
    let mut qemu = "qemu-system-aarch64".to_string();
    let mut mount_directory = "bin/".to_string();
    let mut smp = "4".to_string();
    let mut qemu_efi = "QEMU_EFI.fd".to_string();
    let mut is_debug = false;

    // Parse options
    while let Some(v) = args.next() {
        if v == "-e" || v == "--emulator" {
            try_get_argument!(args, qemu, "Failed to get the emulator path", 1);
        } else if v == "-p" || v == "--smp" {
            try_get_argument!(args, smp, "Failed to get the number of processors", 1);
        } else if v == "-d" || v == "--mount-directory" {
            try_get_argument!(
                args,
                mount_directory,
                "Failed to get the mount directory to mount",
                1
            );
        } else if v == "--debug" {
            is_debug = true;
        } else if v == "--bios" {
            try_get_argument!(args, qemu_efi, "Failed to get the path of OVMF", 1);
        }
    }

    let mut qemu_command = Command::new(qemu);
    qemu_command.args([
        "-machine",
        "virt,virtualization=on,iommu=smmuv3",
        "-smp",
        smp.as_str(),
        "-nographic",
        "-bios",
        qemu_efi.as_str(),
        "-drive",
        format!("file=fat:rw:{mount_directory},format=raw,media=disk").as_str(),
    ]);
    if is_debug {
        qemu_command.args(["-monitor", "telnet::1234,server,nowait"]);
    }

    let exit_status = qemu_command
        .spawn()
        .expect("Failed to run the emulator")
        .wait()
        .unwrap();
    if !exit_status.success() {
        exit(exit_status.code().unwrap());
    }
}

fn write_bin(mut args: Args) {
    // default settings
    let mut mount_directory = "/mnt/".to_string();
    let mut output_directory = "bin/EFI".to_string();
    let mut device = "".to_string();

    // Parse options
    while let Some(v) = args.next() {
        if v == "-d" || v == "--device" {
            try_get_argument!(args, device, "Failed to get the device to mount", 1);
        } else if v == "-o" || v == "--output-dir" {
            try_get_argument!(args, output_directory, "Failed to get the path to copy", 1);
        } else if v == "-p" || v == "--mount-point" {
            try_get_argument!(args, mount_directory, "Failed to get the path to mount", 1);
        }
    }

    if device.is_empty() {
        eprintln!("The device is not specified");
        show_help();
        exit(1);
    }

    // Mount
    let status = Command::new("mount")
        .args([device.as_str(), mount_directory.as_str()])
        .spawn()
        .expect("Failed to mount")
        .wait()
        .expect("Failed to mount");
    if !status.success() {
        eprintln!("Failed to mount the device");
        exit(status.code().unwrap());
    }

    // Copy
    let result = std::fs::copy(output_directory, mount_directory.as_str());

    // Umount
    let status = Command::new("umount")
        .arg(mount_directory.as_str())
        .spawn()
        .expect("Failed to umount")
        .wait()
        .expect("Failed to umount");
    if !status.success() {
        eprintln!("Failed to umount the device");
        exit(status.code().unwrap());
    }

    if result.is_err() {
        eprintln!("Failed to copy binaries: {:?}", result.unwrap_err());
        exit(1);
    }
}

fn show_help() {
    println!("\
Hypervisor Builder
Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST) All rights reserved.

Usage: ./build.rs [global options] command [command options]

Global Options:
  (-m | --manager) package_manager_path : Specify the path of package manager like cargo
  (-h | --help) : Show this message

Command List:
  build : Build the hypervisor
  run   : Run the hypervisor on the emulator
  write : Write the hypervisor binaries into USB memory
  help  : Show this message

Command Options:
build:
  -p | --parallel : Build the bootloader and kernel in parallel(This option is only for build without errors)
  (-f | --features) features : Specify build features (`features` is comma separated)
    Example: -f i210,mt27800
  -r | --release  : Release Build
  (-o | --output-dir) directory : Modify the output directory of built binaries

run:
  (-e | --emulator) qemu_path : Modify qemu path
  (-o | --output-dir) directory : Modify the output directory of built binaries
  (-p | --smp) smp : Modify the number of virtual processors
  (-d | --mount-directory) : Modify the directory path to mount as virtual FAT device
  --bios path : Specify the OVMF image
  --debug : Enable debug system

write:
  (-d | --device) : Specify the device to write (Required)
  (-p | --mount-point) : Modify the path to mount
  (-o | --output-dir) directory : Modify the output directory of built binaries
        ");
}
