// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! EFI Simple Text Output Protocol
//!

use crate::EfiStatus;

#[repr(C)]
pub struct EfiOutputProtocol {
    reset: extern "efiapi" fn(*const EfiOutputProtocol, bool) -> EfiStatus,
    output_string: extern "efiapi" fn(*const EfiOutputProtocol, *const u16) -> EfiStatus,
    test_string: usize,
    query_mode: usize,
    set_mode: usize,
    set_attribute: usize,
    clear_screen: usize,
    set_cursor_position: usize,
    enable_cursor: usize,
    mode: usize,
}

impl EfiOutputProtocol {
    /// Clear the screen and move the cursor to top
    ///
    /// # Arguments
    /// * `extended_verification` - should execute extended verification(this will be passed to UEFI)
    #[allow(dead_code)]
    pub fn reset(&self, extended_verification: bool) -> EfiStatus {
        (self.reset)(self as *const _, extended_verification)
    }

    /// Print the string
    ///
    /// # Arguments
    /// * `string` - string to print (Should avoid to contain non ASCII chars)
    pub fn output(&self, string: &str) -> EfiStatus {
        let mut buf = [0; 256];
        let mut pointer = 0;

        for x in string.encode_utf16() {
            if x == '\n' as u16 {
                buf[pointer] = 0;
                let status = (self.output_string)(self as *const _, buf.as_ptr());
                if status != EfiStatus::EfiSuccess {
                    return status;
                }
                pointer = 0;
                let cr_lf = ['\r' as u16, '\n' as u16, '\0' as u16];
                let status = (self.output_string)(self as *const _, cr_lf.as_ptr());
                if status != EfiStatus::EfiSuccess {
                    return status;
                }
            } else {
                if pointer >= buf.len() - 1 {
                    let status = (self.output_string)(self as *const _, buf.as_ptr());
                    if status != EfiStatus::EfiSuccess {
                        return status;
                    }
                    pointer = 0;
                }
                buf[pointer] = x;
                pointer += 1;
            }
        }
        buf[pointer] = 0;
        (self.output_string)(self as *const _, buf.as_ptr())
    }
}
