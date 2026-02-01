/**
 * @file memory_region.hpp
 * @brief Memory region representation and protection flag handling
 */

#pragma once

#include <mach/vm_region.h>
#include <mach/vm_statistics.h>
#include <mach/vm_prot.h>
#include <mach/vm_types.h>

#include <string>

namespace cheatengine {

/**
 * @brief Human-readable representation of memory protection flags
 */
struct ProtectionFlags {
    bool readable{false};       ///< Memory region allows read access
    bool writable{false};       ///< Memory region allows write access  
    bool executable{false};     ///< Memory region allows code execution

    /**
     * @brief Convert native vm_prot_t flags to ProtectionFlags
     * @param protection Native Mach VM protection flags
     * @return ProtectionFlags Human-readable protection information
     */
    static ProtectionFlags fromNative(vm_prot_t protection);
    
    /**
     * @brief Get a concise string representation (e.g., "RWX", "R--")
     * @return std::string Short protection flag representation
     */
    std::string toString() const;
    
    /**
     * @brief Get a detailed string with explanatory context
     * @return std::string Verbose protection description with context
     */
    std::string toDetailedString() const;
};

/**
 * @brief Represents a contiguous region of virtual memory
 */
struct MemoryRegion {
    mach_vm_address_t start_address{0};     ///< Starting virtual address of the region
    mach_vm_size_t size{0};                 ///< Size of the region in bytes
    vm_prot_t protection{VM_PROT_NONE};     ///< Native Mach VM protection flags
    std::string category;                   ///< Human-readable category (STACK, HEAP, etc.)
    bool is_shared{false};                  ///< Whether region is shared between processes

    /**
     * @brief Get human-readable protection flags
     * @return ProtectionFlags Human-readable representation of permissions
     */
    ProtectionFlags flags() const { return ProtectionFlags::fromNative(protection); }
    
    // Convenience methods for checking region properties.
    
    /**
     * @brief Check if region allows read access
     * @return true if region is readable
     */
    bool isReadable() const { return (protection & VM_PROT_READ) != 0; }
    
    /**
     * @brief Check if region allows write access
     * @return true if region is writable
     */
    bool isWritable() const { return (protection & VM_PROT_WRITE) != 0; }
    
    /**
     * @brief Check if region allows code execution
     * @return true if region is executable
     */
    bool isExecutable() const { return (protection & VM_PROT_EXECUTE) != 0; }
    
    // Address calculation methods.
    
    /**
     * @brief Get the ending address of the region
     * @return mach_vm_address_t Address immediately after the region
     */
    mach_vm_address_t endAddress() const { return start_address + size; }
    
    /**
     * @brief Check if an address falls within this region
     * @param address Virtual address to check
     * @return true if address is within region boundaries
     */
    bool containsAddress(mach_vm_address_t address) const {
        return address >= start_address && address < endAddress();
    }
    
    /**
     * @brief Get human-readable size representation
     * @return std::string Size formatted with appropriate units (KB, MB, GB)
     */
    std::string sizeString() const;
};

/**
 * @brief Categorize a memory region based on its properties
 * @param info Detailed region information from mach_vm_region
 * @param address Starting address of the region
 * @return std::string Human-readable category name
 */
std::string categorizeRegion(const vm_region_submap_info_64& info, mach_vm_address_t address);

} // namespace cheatengine
