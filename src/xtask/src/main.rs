// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

extern crate toml;

use std::env::Args;
use std::fs;
use std::process::{Command, Stdio, exit};

use clap::Parser;

const HYPERVISOR_BOOTLOADER_NAME: &str = "hypervisor_bootloader";
const HYPERVISOR_KERNEL_NAME: &str = "hypervisor_kernel";
const CARGO_FILE_NAME: &str = "Cargo.toml";
const HYPERVISOR_BOOTLOADER_TRIPLE: &str = "aarch64-unknown-uefi";
const HYPERVISOR_KERNEL_TRIPLE: &str = "aarch64-unknown-none-softfloat";

#[derive(clap::Parser)]
#[command(author, version, about = "Hypervisor Builder", long_about = None)]
struct TaskArgs {
    /// Specify the path of package manager like cargo
    #[arg(short = 'm', long)]
    manager: Option<String>,

    #[command(subcommand)]
    command: TaskCommand,
}

#[derive(clap::Subcommand)]
enum TaskCommand {
    /// Build the hypervisor
    Build {
        /// Build the bootloader and kernel in parallel
        #[arg(short, long)]
        parallel: bool,

        /// Specify build features (comma separated)
        #[arg(short, long)]
        features: Option<String>,

        /// Release Build
        #[arg(short, long)]
        release: bool,

        /// Modify the output directory of built binaries
        #[arg(short, long)]
        output_dir: Option<String>,
    },

    /// Run the hypervisor on the emulator
    Run {
        /// Modify qemu path
        #[arg(short = 'e', long)]
        emulator: Option<String>,

        /// Modify the number of virtual processors
        #[arg(short, long)]
        smp: Option<String>,

        /// Modify the memory size
        #[arg(short, long)]
        memory: Option<String>,

        /// Modify the directory path to mount as virtual FAT device
        #[arg(short = 'd', long)]
        mount_directory: Option<String>,

        /// Enable debug system
        #[arg(long)]
        debug: bool,

        /// Specify the OVMF image
        #[arg(long)]
        bios: Option<String>,
    },

    /// Write the hypervisor binaries into USB memory
    Write {
        /// Specify the device to write (Required)
        #[arg(short = 'd', long, required = true)]
        device: String,

        /// Modify the path to mount
        #[arg(short = 'p', long)]
        mount_point: Option<String>,

        /// Modify the output directory of built binaries
        #[arg(short, long)]
        output_dir: Option<String>,
    },
}

fn main() {
    let args = TaskArgs::parse();

    // Set default cargo path or use the one provided
    let cargo_path = args.manager.unwrap_or_else(|| "cargo".to_string());

    match args.command {
        TaskCommand::Build {
            parallel,
            features,
            release,
            output_dir,
        } => build(parallel, features, release, output_dir, &cargo_path),
        TaskCommand::Run {
            emulator,
            smp,
            memory,
            mount_directory,
            debug,
            bios,
        } => run(emulator, smp, memory, mount_directory, debug, bios),
        TaskCommand::Write {
            device,
            mount_point,
            output_dir,
        } => write_bin(device, mount_point, output_dir),
    }
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

fn build(
    parallel: bool,
    features: Option<String>,
    is_release: bool,
    output_dir: Option<String>,
    cargo_path: &String,
) {
    // Default settings
    let mut is_kernel_embedded = false;
    let mut is_parallel = parallel; // Create a mutable copy of the parallel parameter
    let mut bootloader_cargo_args: Vec<String> = vec!["build".to_string()];
    let mut kernel_cargo_args: Vec<String> = vec!["build".to_string()];
    let mut output_directory = output_dir.unwrap_or_else(|| "bin/EFI/BOOT".to_string());
    let hypervisor_bootloader_suffix = ".efi";
    let hypervisor_bootloader_output_name = "BOOTAA64.EFI";

    // Path
    let mut bootloader_path = std::env::current_dir().unwrap();
    let mut kernel_path = std::env::current_dir().unwrap();
    bootloader_path.push(HYPERVISOR_BOOTLOADER_NAME);
    kernel_path.push(HYPERVISOR_KERNEL_NAME);
    let bootloader_path = bootloader_path;
    let kernel_path = kernel_path;

    // Process features if provided
    if let Some(f) = features {
        // List up supported features
        let mut bootloader_cargo_toml_path = bootloader_path.clone();
        let mut kernel_cargo_toml_path = kernel_path.clone();
        bootloader_cargo_toml_path.push(CARGO_FILE_NAME);
        kernel_cargo_toml_path.push(CARGO_FILE_NAME);
        let bootloader_features = get_features(bootloader_cargo_toml_path.to_str().unwrap());
        let kernel_features = get_features(kernel_cargo_toml_path.to_str().unwrap());

        // Process features
        let mut hypervisor_bootloader_features_list = Vec::<String>::new();
        let mut hypervisor_kernel_features_list = Vec::<String>::new();

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
    }

    // Add release flag if needed
    if is_release {
        bootloader_cargo_args.push("--release".to_string());
        kernel_cargo_args.push("--release".to_string());
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

fn run(
    emulator: Option<String>,
    smp: Option<String>,
    memory: Option<String>,
    mount_directory: Option<String>,
    is_debug: bool,
    bios: Option<String>,
) {
    // default settings
    let qemu = emulator.unwrap_or_else(|| "qemu-system-aarch64".to_string());
    let mount_dir = mount_directory.unwrap_or_else(|| "bin/".to_string());
    let smp_value = smp.unwrap_or_else(|| "4".to_string());
    let memory_value = memory.unwrap_or_else(|| "1G".to_string());
    let qemu_efi = bios.unwrap_or_else(|| "QEMU_EFI.fd".to_string());

    let mut qemu_command = Command::new(qemu);
    qemu_command.args([
        "-m",
        memory_value.as_str(),
        "-cpu",
        "a64fx",
        "-machine",
        "virt,virtualization=on,iommu=smmuv3",
        "-smp",
        smp_value.as_str(),
        "-nographic",
        "-bios",
        qemu_efi.as_str(),
        "-drive",
        format!("file=fat:rw:{mount_dir},format=raw,media=disk").as_str(),
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

fn write_bin(device: String, mount_point: Option<String>, output_dir: Option<String>) {
    // default settings
    let mount_directory = mount_point.unwrap_or_else(|| "/mnt/".to_string());
    let output_directory = output_dir.unwrap_or_else(|| "bin/EFI".to_string());

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

// The show_help function is removed as clap will auto-generate help
