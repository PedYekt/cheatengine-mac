/**
 * @file memory_region.hpp
 * @brief Memory region representation and protection flag handling
 * 
 * This file demonstrates how to work with virtual memory regions and protection
 * flags on macOS, providing educational insight into memory management concepts
 * and security mechanisms.
 * 
 * Educational Focus:
 * - Virtual memory protection mechanisms (read/write/execute permissions)
 * - Memory region categorization and analysis
 * - Translation between system types and user-friendly representations
 * - Memory layout understanding and visualization
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
 * 
 * This structure demonstrates how to translate low-level system protection
 * flags into educational, human-readable format. It provides insight into
 * how operating systems implement memory security.
 * 
 * Educational Concepts:
 * - Memory protection mechanisms (NX bit, write protection, etc.)
 * - Security implications of different permission combinations
 * - Common protection patterns in process memory layout
 */
struct ProtectionFlags {
    bool readable{false};       ///< Memory region allows read access
    bool writable{false};       ///< Memory region allows write access  
    bool executable{false};     ///< Memory region allows code execution

    /**
     * @brief Convert native vm_prot_t flags to ProtectionFlags
     * @param protection Native Mach VM protection flags
     * @return ProtectionFlags Human-readable protection information
     * 
     * Demonstrates how to translate system-level protection flags into
     * educational format, showing the mapping between low-level bits
     * and high-level security concepts.
     */
    static ProtectionFlags fromNative(vm_prot_t protection);
    
    /**
     * @brief Get a concise string representation (e.g., "RWX", "R--")
     * @return std::string Short protection flag representation
     * 
     * Provides the traditional Unix-style permission display format
     * for educational familiarity and compact display.
     */
    std::string toString() const;
    
    /**
     * @brief Get a detailed string with educational explanations
     * @return std::string Verbose protection description with context
     * 
     * Provides educational descriptions that explain what each permission
     * means and why different combinations are used in practice.
     */
    std::string toDetailedString() const;
};

/**
 * @brief Represents a contiguous region of virtual memory
 * 
 * This structure demonstrates how to capture and analyze virtual memory regions,
 * providing educational insight into process memory layout and organization.
 * 
 * Educational Concepts:
 * - Virtual memory region structure and metadata
 * - Memory protection and security boundaries
 * - Process memory layout patterns (stack, heap, code, data)
 * - Address space organization and management
 */
struct MemoryRegion {
    mach_vm_address_t start_address{0};     ///< Starting virtual address of the region
    mach_vm_size_t size{0};                 ///< Size of the region in bytes
    vm_prot_t protection{VM_PROT_NONE};     ///< Native Mach VM protection flags
    std::string category;                   ///< Human-readable category (STACK, HEAP, etc.)
    bool is_shared{false};                  ///< Whether region is shared between processes

    /**
     * @brief Get human-readable protection flags
     * @return ProtectionFlags Educational representation of permissions
     * 
     * Converts low-level protection flags to educational format for analysis.
     */
    ProtectionFlags flags() const { return ProtectionFlags::fromNative(protection); }
    
    // Convenience methods for checking region properties - demonstrate bit manipulation
    
    /**
     * @brief Check if region allows read access
     * @return true if region is readable
     * 
     * Demonstrates bit manipulation for checking specific permission flags.
     */
    bool isReadable() const { return (protection & VM_PROT_READ) != 0; }
    
    /**
     * @brief Check if region allows write access
     * @return true if region is writable
     * 
     * Shows how write permissions are checked and their security implications.
     */
    bool isWritable() const { return (protection & VM_PROT_WRITE) != 0; }
    
    /**
     * @brief Check if region allows code execution
     * @return true if region is executable
     * 
     * Demonstrates the NX (No eXecute) bit concept and code/data separation.
     */
    bool isExecutable() const { return (protection & VM_PROT_EXECUTE) != 0; }
    
    // Address calculation methods - demonstrate virtual memory arithmetic
    
    /**
     * @brief Get the ending address of the region
     * @return mach_vm_address_t Address immediately after the region
     * 
     * Demonstrates virtual address arithmetic and region boundary calculation.
     */
    mach_vm_address_t endAddress() const { return start_address + size; }
    
    /**
     * @brief Check if an address falls within this region
     * @param address Virtual address to check
     * @return true if address is within region boundaries
     * 
     * Demonstrates address range checking and virtual memory boundary concepts.
     * Educational Note: Shows half-open interval [start, end) convention.
     */
    bool containsAddress(mach_vm_address_t address) const {
        return address >= start_address && address < endAddress();
    }
    
    /**
     * @brief Get human-readable size representation
     * @return std::string Size formatted with appropriate units (KB, MB, GB)
     * 
     * Provides educational size formatting that makes large memory regions
     * easier to understand and compare.
     */
    std::string sizeString() const;
};

/**
 * @brief Categorize a memory region based on its properties
 * @param info Detailed region information from mach_vm_region
 * @param address Starting address of the region
 * @return std::string Human-readable category name
 * 
 * This function demonstrates how to analyze memory region metadata to
 * determine the likely purpose and type of each region in a process.
 * 
 * Educational Value:
 * - Shows how to interpret vm_region_submap_info_64 data
 * - Demonstrates memory layout pattern recognition
 * - Provides insight into how different types of memory are organized
 * - Illustrates the relationship between memory usage and region properties
 * 
 * Categories Identified:
 * - STACK: Thread stack regions
 * - HEAP: Dynamic allocation regions  
 * - CODE: Executable program code
 * - DATA: Program data and constants
 * - LIBRARY: Shared library mappings
 * - GUARD: Memory protection guard pages
 * - UNKNOWN: Unclassified regions
 */
std::string categorizeRegion(const vm_region_submap_info_64& info, mach_vm_address_t address);

} // namespace cheatengine
