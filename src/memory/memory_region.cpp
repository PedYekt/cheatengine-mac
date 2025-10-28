#include "cheatengine/memory/memory_region.hpp"

#include <sstream>

namespace {

bool isHeapTag(int user_tag)
{
    switch (user_tag) {
    case VM_MEMORY_MALLOC:
    case VM_MEMORY_MALLOC_SMALL:
    case VM_MEMORY_MALLOC_LARGE:
    case VM_MEMORY_MALLOC_TINY:
    case VM_MEMORY_MALLOC_LARGE_REUSABLE:
#ifdef VM_MEMORY_ANALYSIS_TOOL
    case VM_MEMORY_ANALYSIS_TOOL:
#endif
        return true;
    default:
        return false;
    }
}

bool isSharedLibTag(int user_tag)
{
    switch (user_tag) {
    case VM_MEMORY_DYLIB:
#ifdef VM_MEMORY_DYLIB_CODE
    case VM_MEMORY_DYLIB_CODE:
#endif
    case VM_MEMORY_OS_ALLOC_ONCE:
    case VM_MEMORY_SHARED_PMAP:
#ifdef VM_MEMORY_IOKIT
    case VM_MEMORY_IOKIT:
#endif
        return true;
    default:
        return false;
    }
}

} // namespace

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
    std::ostringstream oss;
    oss << (readable ? 'r' : '-')
        << (writable ? 'w' : '-')
        << (executable ? 'x' : '-');
    return oss.str();
}

std::string ProtectionFlags::toDetailedString() const
{
    std::ostringstream oss;
    
    if (readable || writable || executable) {
        bool first = true;
        if (readable) {
            oss << "Read";
            first = false;
        }
        if (writable) {
            if (!first) oss << ", ";
            oss << "Write";
            first = false;
        }
        if (executable) {
            if (!first) oss << ", ";
            oss << "Execute";
        }
    } else {
        oss << "No Access";
    }
    
    return oss.str();
}

std::string categorizeRegion(const vm_region_submap_info_64& info, mach_vm_address_t)
{
    if (info.is_submap) {
        return "Submap";
    }

    if (info.user_tag == VM_MEMORY_STACK) {
        return "Stack";
    }

    if (isHeapTag(static_cast<int>(info.user_tag))) {
        return "Heap";
    }

    if (isSharedLibTag(static_cast<int>(info.user_tag))) {
        return "SharedLib";
    }

    if ((info.protection & VM_PROT_EXECUTE) != 0) {
        return "Code";
    }

    if (info.share_mode == SM_SHARED
#ifdef SM_TRUESHARED
        || info.share_mode == SM_TRUESHARED
#endif
    ) {
        return "Shared";
    }

    return "Data";
}

std::string MemoryRegion::sizeString() const
{
    std::ostringstream oss;
    
    if (size >= 1024 * 1024 * 1024) {
        oss << (size / (1024.0 * 1024.0 * 1024.0)) << " GB";
    } else if (size >= 1024 * 1024) {
        oss << (size / (1024.0 * 1024.0)) << " MB";
    } else if (size >= 1024) {
        oss << (size / 1024.0) << " KB";
    } else {
        oss << size << " bytes";
    }
    
    return oss.str();
}

} // namespace cheatengine
