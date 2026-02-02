#pragma once

#include <mach/vm_region.h>
#include <mach/vm_statistics.h>
#include <mach/vm_prot.h>
#include <mach/vm_types.h>
#include <string>

namespace cheatengine {

struct ProtectionFlags {
    bool readable{false};
    bool writable{false};
    bool executable{false};

    static ProtectionFlags fromNative(vm_prot_t protection);
    std::string toString() const;
};

struct MemoryRegion {
    mach_vm_address_t start_address{0};
    mach_vm_size_t size{0};
    vm_prot_t protection{VM_PROT_NONE};
    std::string category;
    bool is_shared{false};

    ProtectionFlags flags() const { return ProtectionFlags::fromNative(protection); }
    bool isReadable() const { return (protection & VM_PROT_READ) != 0; }
    bool isWritable() const { return (protection & VM_PROT_WRITE) != 0; }
    mach_vm_address_t endAddress() const { return start_address + size; }
    std::string sizeString() const;
};

std::string categorizeRegion(const vm_region_submap_info_64& info, mach_vm_address_t address);

} // namespace cheatengine
