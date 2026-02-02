#include "cheatengine/memory/memory_region.hpp"

namespace cheatengine {

ProtectionFlags ProtectionFlags::fromNative(vm_prot_t protection)
{
    ProtectionFlags flags;
    flags.readable = (protection & VM_PROT_READ) != 0;
    flags.writable = (protection & VM_PROT_WRITE) != 0;
    flags.executable = (protection & VM_PROT_EXECUTE) != 0;
    return flags;
}

std::string ProtectionFlags::toString() const
{
    std::string s;
    s += readable ? 'r' : '-';
    s += writable ? 'w' : '-';
    s += executable ? 'x' : '-';
    return s;
}

std::string categorizeRegion(const vm_region_submap_info_64& info, mach_vm_address_t)
{
    if (info.is_submap) return "Submap";
    if (info.user_tag == VM_MEMORY_STACK) return "Stack";

    // Heap tags
    if (info.user_tag == VM_MEMORY_MALLOC || info.user_tag == VM_MEMORY_MALLOC_SMALL ||
        info.user_tag == VM_MEMORY_MALLOC_LARGE || info.user_tag == VM_MEMORY_MALLOC_TINY ||
        info.user_tag == VM_MEMORY_MALLOC_LARGE_REUSABLE) {
        return "Heap";
    }

    // Shared lib tags
    if (info.user_tag == VM_MEMORY_DYLIB || info.user_tag == VM_MEMORY_OS_ALLOC_ONCE ||
        info.user_tag == VM_MEMORY_SHARED_PMAP) {
        return "SharedLib";
    }

    if ((info.protection & VM_PROT_EXECUTE) != 0) return "Code";
    if (info.share_mode == SM_SHARED) return "Shared";

    return "Data";
}

std::string MemoryRegion::sizeString() const
{
    if (size >= 1024 * 1024 * 1024) {
        return std::to_string(size / (1024 * 1024 * 1024)) + " GB";
    } else if (size >= 1024 * 1024) {
        return std::to_string(size / (1024 * 1024)) + " MB";
    } else if (size >= 1024) {
        return std::to_string(size / 1024) + " KB";
    }
    return std::to_string(size) + " bytes";
}

} // namespace cheatengine
