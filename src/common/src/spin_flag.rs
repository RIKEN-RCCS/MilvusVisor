// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

use core::sync::atomic::{AtomicBool, Ordering};

use crate::cpu::{clean_and_invalidate_data_cache, isb};

pub struct SpinLockFlag(AtomicBool);

impl Default for SpinLockFlag {
    fn default() -> Self {
        Self::new()
    }
}

impl SpinLockFlag {
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    #[inline(always)]
    pub fn try_lock_weak(&self) -> Result<(), bool> {
        clean_and_invalidate_data_cache(self.0.as_ptr() as usize);
        isb();
        self.0
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .and_then(|old| if !old { Ok(()) } else { Err(false) })
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
        clean_and_invalidate_data_cache(self.0.as_ptr() as usize);
        isb();
        self.0.store(false, Ordering::Release)
    }

    #[inline(always)]
    pub fn is_locked(&self) -> bool {
        clean_and_invalidate_data_cache(self.0.as_ptr() as usize);
        isb();
        self.0.load(Ordering::Relaxed)
    }
}
