// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use core::sync::atomic::{AtomicBool, Ordering};

pub struct SpinLockFlag(AtomicBool);

impl SpinLockFlag {
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    #[inline(always)]
    pub fn try_lock_weak(&self) -> Result<(), ()> {
        self.0
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .and_then(|old| if old == false { Ok(()) } else { Err(false) })
            .or(Err(()))
    }

    #[inline(always)]
    pub fn lock(&self) {
        while self.try_lock_weak().is_err() {
            while self.is_locked() {
                core::hint::spin_loop();
            }
        }
    }

    #[inline(always)]
    pub fn unlock(&self) {
        self.0.store(false, Ordering::Release)
    }

    #[inline(always)]
    pub fn is_locked(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}
