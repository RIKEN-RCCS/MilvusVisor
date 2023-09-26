// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use std::process::{Command, Stdio};

fn main() {
    set_environments();
}

fn set_environments() {
    if let Ok(output) = Command::new("rustc")
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        if let Ok(rustc_version) = std::str::from_utf8(output.stdout.as_slice()) {
            println!("cargo:rustc-env=RUSTC_VERSION={rustc_version}");
        }
    }

    if let Ok(output) = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        if output.status.success() {
            if let Ok(git_hash) = std::str::from_utf8(output.stdout.as_slice()) {
                println!("cargo:rustc-env=PROJECT_HASH={git_hash}");
            }
        }
    }
}
