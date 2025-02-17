// Copyright (c) 2022 RIKEN
// Copyright (c) 2022 National Institute of Advanced Industrial Science and Technology (AIST)
// All rights reserved.
//
// This software is released under the MIT License.
// http://opensource.org/licenses/mit-license.php

//!
//! Power State Coordination Interface
//!
//! Supported Version: ~2.0

use common::GeneralPurposeRegisters;
use common::cpu::{get_mpidr_el1, secure_monitor_call};

use crate::handler_panic;
use crate::multi_core::{power_off_cpu, setup_new_cpu};

/// PSCI Function ID List
///
/// If edit this enum, you must adjust TryFrom
#[repr(u64)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PsciFunctionId {
    Version = 0x8400_0000,
    CpuSuspend = 0xC400_0001,
    CpuOff = 0x8400_0002,
    CpuOn = 0xC400_0003,
    AffinityInfo = 0xC400_0004,
    Migrate = 0xC400_0005,
    MigrateInfoType = 0x8400_0006,
    MigrateInfoUpCpu = 0xC400_0007,
    SystemOff = 0x8400_0008,
    SystemReset = 0x8400_0009,
    SystemReset2 = 0xC400_0012,
    MemProtect = 0x8400_0013,
    MemProtectCheckRange = 0xC400_0014,
    PsciFeatures = 0x8400_000A,
    CpuFreeze = 0x8400_000B,
    CpuDefaultSuspend = 0xC400_000C,
    NodeHwState = 0xC400_000D,
    SystemSuspend = 0xC400_000E,
    PsciSetSuspendMode = 0x8400_000F,
    PsciStatResidency = 0xC400_0010,
    PsciStatCount = 0xC400_0011,
}

impl TryFrom<u64> for PsciFunctionId {
    type Error = ();
    fn try_from(id: u64) -> Result<Self, Self::Error> {
        match id {
            x if x == PsciFunctionId::Version as u64 => Ok(PsciFunctionId::Version),
            x if x == PsciFunctionId::CpuSuspend as u64 => Ok(PsciFunctionId::CpuSuspend),
            x if x == PsciFunctionId::CpuOff as u64 => Ok(PsciFunctionId::CpuOff),
            x if x == PsciFunctionId::CpuOn as u64 => Ok(PsciFunctionId::CpuOn),
            x if x == PsciFunctionId::AffinityInfo as u64 => Ok(PsciFunctionId::AffinityInfo),
            x if x == PsciFunctionId::Migrate as u64 => Ok(PsciFunctionId::Migrate),
            x if x == PsciFunctionId::MigrateInfoType as u64 => Ok(PsciFunctionId::MigrateInfoType),
            x if x == PsciFunctionId::MigrateInfoUpCpu as u64 => {
                Ok(PsciFunctionId::MigrateInfoUpCpu)
            }
            x if x == PsciFunctionId::SystemOff as u64 => Ok(PsciFunctionId::SystemOff),
            x if x == PsciFunctionId::SystemReset as u64 => Ok(PsciFunctionId::SystemReset),
            x if x == PsciFunctionId::SystemReset2 as u64 => Ok(PsciFunctionId::SystemReset2),
            x if x == PsciFunctionId::MemProtect as u64 => Ok(PsciFunctionId::MemProtect),
            x if x == PsciFunctionId::MemProtectCheckRange as u64 => {
                Ok(PsciFunctionId::MemProtectCheckRange)
            }
            x if x == PsciFunctionId::PsciFeatures as u64 => Ok(PsciFunctionId::PsciFeatures),
            x if x == PsciFunctionId::CpuFreeze as u64 => Ok(PsciFunctionId::CpuFreeze),
            x if x == PsciFunctionId::CpuDefaultSuspend as u64 => {
                Ok(PsciFunctionId::CpuDefaultSuspend)
            }
            x if x == PsciFunctionId::NodeHwState as u64 => Ok(PsciFunctionId::NodeHwState),
            x if x == PsciFunctionId::SystemSuspend as u64 => Ok(PsciFunctionId::SystemSuspend),
            x if x == PsciFunctionId::PsciSetSuspendMode as u64 => {
                Ok(PsciFunctionId::PsciSetSuspendMode)
            }
            x if x == PsciFunctionId::PsciStatResidency as u64 => {
                Ok(PsciFunctionId::PsciStatResidency)
            }
            x if x == PsciFunctionId::PsciStatCount as u64 => Ok(PsciFunctionId::PsciStatCount),
            _ => Err(()),
        }
    }
}

/// PSCI ReturnCode List
///
/// If edit this enum, you must adjust TryFrom
#[repr(i32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(dead_code)]
pub enum PsciReturnCode {
    Success = 0,
    NotSupported = -1,
    InvalidParameters = -2,
    Denied = -3,
    AlreadyOn = -4,
    OnPending = -5,
    InternalFailure = -6,
    NotPresent = -7,
    Disabled = -8,
    InvalidAddress = -9,
}

impl TryFrom<i32> for PsciReturnCode {
    type Error = ();
    fn try_from(c: i32) -> Result<Self, Self::Error> {
        if c > 0 || c < PsciReturnCode::InvalidAddress as i32 {
            Err(())
        } else {
            unsafe { Ok(core::mem::transmute::<i32, Self>(c)) }
        }
    }
}

pub fn handle_psci_call(function_id: PsciFunctionId, regs: &mut GeneralPurposeRegisters) {
    pr_debug!("PSCI Function Call: {:?}", function_id);

    if function_id == PsciFunctionId::CpuOn {
        pr_debug!("CPU ON: MPIDR: {:#X}", regs[1]);
        setup_new_cpu(regs);
    } else if function_id == PsciFunctionId::CpuOff {
        let result = power_off_cpu();
        handler_panic!(
            regs,
            "Failed to power off the cpu (MPIDR: {:#X}): {:?}",
            get_mpidr_el1(),
            PsciReturnCode::try_from(result)
        );
    } else {
        #[cfg(feature = "fast_restore")]
        if function_id == PsciFunctionId::SystemOff
            || function_id == PsciFunctionId::SystemReset
            || function_id == PsciFunctionId::SystemReset2
        {
            println!("Trap power_off/reboot");
            crate::fast_restore::enter_restore_process();
        }
        secure_monitor_call(regs);
    }
}

pub fn call_psci_function(function_id: PsciFunctionId, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    let mut regs: GeneralPurposeRegisters = [0; 32];
    regs[0] = function_id as u64;
    regs[1] = arg0;
    regs[2] = arg1;
    regs[3] = arg2;
    secure_monitor_call(&mut regs);
    regs[0]
}
