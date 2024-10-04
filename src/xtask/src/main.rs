// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate toml;

use std::env::Args;
use std::fs;
use std::process::{Command, Stdio, exit};

const HYPERVISOR_BOOTLOADER_NAME: &str = "hypervisor_bootloader";
const HYPERVISOR_KERNEL_NAME: &str = "hypervisor_kernel";
const CARGO_FILE_NAME: &str = "Cargo.toml";
const HYPERVISOR_BOOTLOADER_TRIPLE: &str = "aarch64-unknown-uefi";
const HYPERVISOR_KERNEL_TRIPLE: &str = "aarch64-unknown-none-softfloat";

fn main() {
    // default settings
    let mut cargo_path = "cargo".to_string();
    let mut args = std::env::args();
    // Skip xtask binary path
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

fn get_features(cargo_toml_path: &str) -> Vec<String> {
    toml::from_str::<toml::Table>(fs::read_to_string(cargo_toml_path).unwrap().as_str())
        .unwrap()
        .get("features")
        .expect("Failed to get `[features]`")
        .as_table()
        .expect("`[features]` is invalid.")
        .iter()
        .map(|(k, _)| k.clone())
        .collect::<Vec<_>>()
}

fn build(mut args: Args, cargo_path: &String) {
    // Default settings
    let mut is_parallel = false;
    let mut is_release = false;
    let mut is_kernel_embedded = false;
    let mut bootloader_cargo_args: Vec<String> = vec!["build".to_string()];
    let mut kernel_cargo_args: Vec<String> = vec!["build".to_string()];
    let mut output_directory = "bin/EFI/BOOT".to_string();
    let hypervisor_bootloader_suffix = ".efi";
    let hypervisor_bootloader_output_name = "BOOTAA64.EFI";

    // Path
    let mut bootloader_path = std::env::current_dir().unwrap();
    let mut kernel_path = std::env::current_dir().unwrap();
    bootloader_path.push(HYPERVISOR_BOOTLOADER_NAME);
    kernel_path.push(HYPERVISOR_KERNEL_NAME);
    let bootloader_path = bootloader_path;
    let kernel_path = kernel_path;

    // Parse options
    while let Some(v) = args.next() {
        if v == "-f" || v == "--features" {
            // List up supported features
            let mut bootloader_cargo_toml_path = bootloader_path.clone();
            let mut kernel_cargo_toml_path = kernel_path.clone();
            bootloader_cargo_toml_path.push(CARGO_FILE_NAME);
            kernel_cargo_toml_path.push(CARGO_FILE_NAME);
            let bootloader_features = get_features(bootloader_cargo_toml_path.to_str().unwrap());
            let kernel_features = get_features(kernel_cargo_toml_path.to_str().unwrap());

            // Get features from command line
            let f: String;
            let mut hypervisor_bootloader_features_list = Vec::<String>::new();
            let mut hypervisor_kernel_features_list = Vec::<String>::new();
            try_get_argument!(args, f, "Failed to get features", 1);

            for feature in f.split_terminator(',') {
                let feature = feature.to_string();
                let mut is_supported = false;

                if bootloader_features.contains(&feature) {
                    hypervisor_bootloader_features_list.push(feature.clone());
                    is_supported = true;
                }
                if kernel_features.contains(&feature) {
                    hypervisor_kernel_features_list.push(feature.clone());
                    is_supported = true;
                }
                if !is_supported {
                    eprintln!(
                        "'{feature}' is unknown feature\nSupported features:\n\tLoader: {:?},\n\tKernel: {:?}",
                        bootloader_features, kernel_features
                    );
                    exit(1);
                }
                if feature == "embed_kernel" {
                    is_kernel_embedded = true;
                }
            }

            bootloader_cargo_args.push("--no-default-features".to_string());
            kernel_cargo_args.push("--no-default-features".to_string());
            bootloader_cargo_args.push("--features".to_string());
            kernel_cargo_args.push("--features".to_string());
            bootloader_cargo_args.push(hypervisor_bootloader_features_list.join(","));
            kernel_cargo_args.push(hypervisor_kernel_features_list.join(","));
        } else if v == "-p" || v == "--parallel" {
            is_parallel = true;
        } else if v == "-r" || v == "--release" {
            is_release = true;
            bootloader_cargo_args.push("--release".to_string());
            kernel_cargo_args.push("--release".to_string());
        } else if v == "-o" || v == "--output-dir" {
            try_get_argument!(
                args,
                output_directory,
                "Failed to get the output directory",
                1
            );
        }
    }

    // Create the command line
    let mut bootloader_command = Command::new(cargo_path);
    let mut kernel_command = Command::new(cargo_path);

    // Set working directory
    bootloader_command.current_dir(bootloader_path);
    kernel_command.current_dir(kernel_path);

    // Set arguments
    bootloader_command.args(bootloader_cargo_args);
    kernel_command.args(kernel_cargo_args);

    if is_kernel_embedded && is_parallel {
        is_parallel = false;
        eprintln!("Parallel build is disabled by 'embed_kernel'");
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
    hypervisor_bootloader_binary_path.push(HYPERVISOR_BOOTLOADER_TRIPLE);
    hypervisor_kernel_binary_path.push("target");
    hypervisor_kernel_binary_path.push(HYPERVISOR_KERNEL_TRIPLE);

    if is_release {
        hypervisor_bootloader_binary_path.push("release");
        hypervisor_kernel_binary_path.push("release");
    } else {
        hypervisor_bootloader_binary_path.push("debug");
        hypervisor_kernel_binary_path.push("debug");
    }
    hypervisor_bootloader_binary_path
        .push(HYPERVISOR_BOOTLOADER_NAME.to_string() + hypervisor_bootloader_suffix);
    hypervisor_kernel_binary_path.push(HYPERVISOR_KERNEL_NAME);

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
    hypervisor_kernel_new_name.push(HYPERVISOR_KERNEL_NAME);
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
    let mut memory = "1G".to_string();
    let mut qemu_efi = "QEMU_EFI.fd".to_string();
    let mut is_debug = false;

    // Parse options
    while let Some(v) = args.next() {
        if v == "-e" || v == "--emulator" {
            try_get_argument!(args, qemu, "Failed to get the emulator path", 1);
        } else if v == "-p" || v == "--smp" {
            try_get_argument!(args, smp, "Failed to get the number of processors", 1);
        } else if v == "-m" || v == "--memory" {
            try_get_argument!(args, memory, "Failed to get the memory size", 1);
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
        "-m",
        memory.as_str(),
        "-cpu",
        "a64fx",
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
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .expect("Failed to run the emulator");
    if !exit_status.status.success() {
        exit(exit_status.status.code().unwrap());
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

Usage: cargo xtask [global options] command [command options]

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
  (-m | --memory) size : Modify the memory size
  (-d | --mount-directory) : Modify the directory path to mount as virtual FAT device
  --bios path : Specify the OVMF image
  --debug : Enable debug system

write:
  (-d | --device) : Specify the device to write (Required)
  (-p | --mount-point) : Modify the path to mount
  (-o | --output-dir) directory : Modify the output directory of built binaries
        ");
}
