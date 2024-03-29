//! CPUID related functionality for relevant topology information.
use alloc::vec::Vec;
use core::convert::TryInto;

use crate::{CoreId, PackageId, ThreadId};

/// Silly helper trait for computing power of two
trait PowersOf2 {
    fn log2(self) -> u8;
}

impl PowersOf2 for u8 {
    fn log2(self) -> u8 {
        7 - self.leading_zeros() as u8
    }
}

fn cpuid_bits_needed(count: u8) -> u8 {
    let mut mask: u8 = 0x80;
    let mut cnt: u8 = 8;

    while (cnt > 0) && ((mask & count) != mask) {
        mask >>= 1;
        cnt -= 1;
    }

    cnt
}

fn get_processor_limits() -> (u8, u8) {
    let cpuid = x86::cpuid::CpuId::new();

    // This is for AMD processors:
    if let Some(info) = cpuid.get_processor_capacity_feature_info() {
        // This is how I think it's supposed to work, but doesn't quite work,
        // that's why we use the x2apic code path to determine topology:
        let max_logical_processor_ids = info.num_phys_threads();
        let smt_max_cores_for_package = info.maximum_logical_processors();

        return (
            max_logical_processor_ids.try_into().unwrap(),
            smt_max_cores_for_package.try_into().unwrap(),
        );
    }
    // This is for Intel processors:
    else if let Some(cparams) = cpuid.get_cache_parameters() {
        let max_logical_processor_ids = cpuid
            .get_feature_info()
            .map_or_else(|| 1, |finfo| finfo.max_logical_processor_ids());

        let mut smt_max_cores_for_package: u8 = 0;
        for (ecx, cache) in cparams.enumerate() {
            if ecx == 0 {
                smt_max_cores_for_package = cache.max_cores_for_package() as u8;
            }
        }

        return (
            max_logical_processor_ids as u8,
            smt_max_cores_for_package as u8,
        );
    }

    unreachable!("Example doesn't support this CPU")
}

/// Given APIC ID, figure out package, core and thread ID.
pub fn get_topology_from_apic_id(xapic_id: u8) -> (ThreadId, CoreId, PackageId) {
    let (max_logical_processor_ids, smt_max_cores_for_package) = get_processor_limits();

    let smt_mask_width: u8 = cpuid_bits_needed(
        (max_logical_processor_ids.next_power_of_two() / smt_max_cores_for_package) - 1,
    );
    let smt_select_mask: u8 = !(u8::max_value() << smt_mask_width);
    let core_mask_width: u8 = cpuid_bits_needed(smt_max_cores_for_package - 1);
    let core_only_select_mask =
        (!(u8::max_value() << (core_mask_width + smt_mask_width))) ^ smt_select_mask;
    let pkg_select_mask = u8::max_value() << (core_mask_width + smt_mask_width);

    let smt_id = xapic_id & smt_select_mask;
    let core_id = (xapic_id & core_only_select_mask) >> smt_mask_width;
    let pkg_id = (xapic_id & pkg_select_mask) >> (core_mask_width + smt_mask_width);

    (smt_id.into(), core_id.into(), pkg_id.into())
}

/// Given x2APIC ID, figure out package, core and thread ID.
pub fn get_topology_from_x2apic_id(x2apic_id: u32) -> (ThreadId, CoreId, PackageId) {
    use x86::cpuid::{ExtendedTopologyLevel, TopologyType};
    let cpuid = x86::cpuid::CpuId::new();
    let mut smt_x2apic_shift: u32 = 0;
    let mut core_x2apic_shift: u32 = 0;

    cpuid.get_extended_topology_info().map_or_else(
        || (/* No topology information available */),
        |topoiter| {
            let topology: Vec<ExtendedTopologyLevel> = topoiter.collect();
            for topolevel in topology.iter() {
                match topolevel.level_type() {
                    TopologyType::SMT => {
                        smt_x2apic_shift = topolevel.shift_right_for_next_apic_id();
                    }
                    TopologyType::Core => {
                        core_x2apic_shift = topolevel.shift_right_for_next_apic_id();
                    }
                    _ => panic!("Topology category not supported."),
                };
            }
        },
    );

    let smt_select_mask = !(u32::max_value() << smt_x2apic_shift);
    let core_select_mask = (!((u32::max_value()) << core_x2apic_shift)) ^ smt_select_mask;
    let pkg_select_mask = u32::max_value() << core_x2apic_shift;

    let smt_id = x2apic_id & smt_select_mask;
    let core_id = (x2apic_id & core_select_mask) >> smt_x2apic_shift;
    let pkg_id = (x2apic_id & pkg_select_mask) >> core_x2apic_shift;

    (
        smt_id.try_into().unwrap(),
        core_id.try_into().unwrap(),
        pkg_id.try_into().unwrap(),
    )
}
