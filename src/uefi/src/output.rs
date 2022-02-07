// Copyright (c) 2022 RIKEN
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! EFI Output Protocol
//!

use super::EfiStatus;

#[repr(C)]
pub struct EfiOutputProtocol {
    reset: extern "C" fn(*const EfiOutputProtocol, bool) -> EfiStatus,
    output: extern "C" fn(*const EfiOutputProtocol, *const u16) -> EfiStatus,
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
    /// 画面を消去してカーソルを一番先頭に持っていく
    #[allow(dead_code)]
    pub fn reset(&self, extended_verification: bool) -> EfiStatus {
        (self.reset)(self as *const _, extended_verification)
    }

    /// 文字列を画面に表示する
    ///
    /// ATTENTION: UTF-16であるため、日本語も扱えるがフォントを持っていないUEFIも多く正しく表示できない可能性あり
    pub fn output(&self, string: &str) -> EfiStatus {
        let mut buf = [0; 256];
        let mut pointer = 0;

        for x in string.encode_utf16() {
            if x == '\n' as u16 {
                buf[pointer] = 0;
                let status = (self.output)(self as *const _, buf.as_ptr());
                if status != EfiStatus::EfiSuccess {
                    return status;
                }
                pointer = 0;
                let cr_lf = ['\r' as u16, '\n' as u16, '\0' as u16];
                let status = (self.output)(self as *const _, cr_lf.as_ptr());
                if status != EfiStatus::EfiSuccess {
                    return status;
                }
            } else {
                if pointer >= buf.len() - 1 {
                    let status = (self.output)(self as *const _, buf.as_ptr());
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
        (self.output)(self as *const _, buf.as_ptr())
    }
}
