/**
 * @file memory_scanner.hpp
 * @brief Memory enumeration and searching using Mach VM APIs
 * 
 * This file demonstrates how to efficiently scan process memory using macOS
 * Mach kernel APIs. It provides educational examples of virtual memory
 * management, memory protection concepts, and efficient memory access patterns.
 * 
 * Educational Focus:
 * - Virtual memory region enumeration using mach_vm_region
 * - Efficient memory reading with page-aligned chunking
 * - Memory protection flag interpretation
 * - Search algorithm optimization for large address spaces
 * - CPU cache-friendly memory access patterns
 */

#pragma once

#include "cheatengine/memory/memory_region.hpp"
#include "cheatengine/memory/value_types.hpp"

#include <mach/mach.h>

#include <vector>

namespace cheatengine {

/**
 * @brief Memory scanner for process introspection and value searching
 * 
 * The MemoryScanner class demonstrates efficient memory analysis techniques
 * using macOS Mach VM APIs. It showcases virtual memory concepts, memory
 * protection mechanisms, and optimization strategies for memory operations.
 * 
 * Educational Concepts Demonstrated:
 * - Virtual memory region enumeration and categorization
 * - Memory protection flags and their security implications
 * - Efficient memory reading with chunked I/O
 * - Search algorithm optimization for large address spaces
 * - CPU cache locality and memory access patterns
 * - Page-aligned memory operations for optimal performance
 * 
 * Mach VM APIs Used:
 * - mach_vm_region: Enumerate memory regions with protection information
 * - mach_vm_read_overwrite: Read memory content efficiently
 * - VM protection flags: Understand memory access permissions
 * 
 * Performance Considerations:
 * - Uses page-aligned reading (4KB chunks) for optimal VM performance
 * - Implements chunked reading to minimize system call overhead
 * - Provides fast search that skips unlikely memory regions
 * - Demonstrates memory access pattern optimization
 */
class MemoryScanner {
public:
    /**
     * @brief Result of a memory value search operation
     * 
     * This structure demonstrates how to capture comprehensive information
     * about search results, including context for educational analysis.
     */
    struct SearchResult {
        mach_vm_address_t address{0};           ///< Virtual address where value was found
        std::vector<std::uint8_t> context;      ///< Memory context around the match
        std::size_t value_size{0};              ///< Size of the matched value in bytes
    };

    /**
     * @brief Enumerate all memory regions in the target process
     * @param task Mach task port for the target process
     * @return std::vector<MemoryRegion> List of memory regions with metadata
     * 
     * This method demonstrates how to use mach_vm_region to walk through
     * a process's virtual memory space and understand its layout.
     * 
     * Educational Concepts:
     * - Virtual memory region enumeration using Mach APIs
     * - Memory region categorization (stack, heap, code, data)
     * - Memory protection flag interpretation
     * - Process memory layout understanding
     * 
     * Implementation Details:
     * - Uses mach_vm_region with VM_REGION_SUBMAP_INFO_64
     * - Handles region merging and categorization
     * - Provides human-readable region type classification
     * 
     * @throws CheatEngineException on Mach API failures
     */
    std::vector<MemoryRegion> enumerate(task_t task) const;
    
    /**
     * @brief Search for a specific value in process memory
     * @param task Mach task port for the target process
     * @param value SearchValue to look for in memory
     * @return std::vector<SearchResult> List of addresses where value was found
     * 
     * This method demonstrates efficient memory searching techniques and
     * showcases how to handle large address spaces systematically.
     * 
     * Educational Concepts:
     * - Systematic memory scanning algorithms
     * - Efficient memory reading with chunked I/O
     * - Value comparison and matching techniques
     * - Memory access optimization strategies
     * 
     * Performance Features:
     * - Page-aligned reading for optimal VM performance
     * - Chunked reading to minimize system call overhead
     * - Context capture around matches for analysis
     * - Skips non-readable memory regions automatically
     * 
     * @throws CheatEngineException on memory access failures
     */
    std::vector<SearchResult> search(task_t task, const SearchValue& value) const;
    
    /**
     * @brief Read a chunk of memory from the target process
     * @param task Mach task port for the target process
     * @param address Starting virtual address to read from
     * @param size Number of bytes to read
     * @param buffer Output buffer to store the read data
     * @return true if read succeeded, false otherwise
     * 
     * This method demonstrates efficient memory reading using Mach VM APIs
     * and showcases proper error handling for memory operations.
     * 
     * Educational Concepts:
     * - Direct memory reading using mach_vm_read_overwrite
     * - Page-aligned memory access optimization
     * - Memory protection boundary handling
     * - Efficient buffer management for system calls
     * 
     * Implementation Notes:
     * - Uses page-aligned chunks for optimal performance
     * - Handles partial reads and memory protection violations
     * - Provides detailed error information on failures
     * 
     * @note This method respects memory protection boundaries and will
     *       fail gracefully on protected or unmapped memory regions.
     */
    bool readChunk(task_t task, mach_vm_address_t address, std::size_t size, std::vector<std::uint8_t>& buffer) const;
    
    // Display and formatting methods - demonstrate educational output formatting
    
    /**
     * @brief Format memory regions for educational display
     * @param regions List of memory regions to format
     * @return std::string Human-readable representation of memory layout
     * 
     * Creates educational output showing virtual memory layout, protection
     * flags, and region categorization. Demonstrates how to present complex
     * system information in an understandable format.
     */
    std::string formatRegions(const std::vector<MemoryRegion>& regions) const;
    
    /**
     * @brief Format search results for educational analysis
     * @param results List of search results to format
     * @return std::string Human-readable representation of search findings
     * 
     * Provides educational output showing memory addresses, context, and
     * analysis information to help understand memory layout and data location.
     */
    std::string formatSearchResults(const std::vector<SearchResult>& results) const;
    
    // Advanced memory operations - demonstrate optimization techniques
    
    /**
     * @brief Read a large memory range using optimized chunking
     * @param task Mach task port for the target process
     * @param start_address Starting address of the range
     * @param total_size Total size of the range to read
     * @param buffer Output buffer for the entire range
     * @return true if the entire range was read successfully
     * 
     * Demonstrates advanced memory reading techniques for large ranges,
     * including chunked I/O, error recovery, and performance optimization.
     * 
     * Educational Concepts:
     * - Large memory range handling strategies
     * - Chunked I/O for system call optimization
     * - Error recovery and partial read handling
     * - Memory bandwidth optimization techniques
     */
    bool readMemoryRange(task_t task, mach_vm_address_t start_address, 
                        mach_vm_size_t total_size, std::vector<std::uint8_t>& buffer) const;
    
    // Enhanced search functionality - demonstrate advanced algorithms
    
    /**
     * @brief Search for a value within a specific memory region
     * @param task Mach task port for the target process
     * @param region Specific memory region to search within
     * @param value SearchValue to look for
     * @return std::vector<SearchResult> Matches found within the region
     * 
     * Demonstrates targeted searching within specific memory regions,
     * useful for understanding how different types of data are stored
     * in different parts of the process address space.
     */
    std::vector<SearchResult> searchInRegion(task_t task, const MemoryRegion& region, 
                                           const SearchValue& value) const;
    
    /**
     * @brief Search for multiple values simultaneously
     * @param task Mach task port for the target process
     * @param values List of SearchValues to look for
     * @return std::vector<SearchResult> All matches found for any value
     * 
     * Demonstrates efficient multi-value searching and shows how to
     * optimize memory scanning when looking for multiple related values.
     */
    std::vector<SearchResult> searchMultipleValues(task_t task, 
                                                  const std::vector<SearchValue>& values) const;
    
    /**
     * @brief Fast search that focuses on likely memory regions
     * @param task Mach task port for the target process
     * @param value SearchValue to look for
     * @return std::vector<SearchResult> Matches found in high-probability regions
     * 
     * Demonstrates search optimization by focusing on memory regions where
     * user data is most likely to be found (stack, heap, data segments).
     * 
     * Educational Value:
     * - Shows understanding of typical memory layout patterns
     * - Demonstrates performance vs. completeness trade-offs
     * - Illustrates memory region categorization practical applications
     */
    std::vector<SearchResult> searchFast(task_t task, const SearchValue& value) const;
    
    // Search result management - demonstrate result analysis
    
    /**
     * @brief Format a single search result with detailed analysis
     * @param result SearchResult to format
     * @param original_value Original SearchValue that was found
     * @return std::string Detailed analysis of the search result
     * 
     * Provides comprehensive analysis of a search result including memory
     * context, potential data structure information, and educational insights
     * about the memory location and its significance.
     */
    std::string formatSearchResultDetailed(const SearchResult& result, const SearchValue& original_value) const;
    
private:
    /// Page-aligned reading for optimal VM performance - demonstrates system optimization
    static constexpr std::size_t CHUNK_SIZE = 4096;

    /// Context bytes around search matches - provides educational analysis context
    static constexpr std::size_t CONTEXT_BYTES = 16;

    /// Search performance and safety limits
    static constexpr std::size_t MAX_SEARCH_RESULTS = 1000;           ///< Limit results to prevent hanging
    static constexpr std::size_t MAX_REGION_SIZE_MB = 100;            ///< Skip regions larger than this in complete search
    static constexpr std::size_t MAX_FAST_SEARCH_REGION_SIZE_MB = 50; ///< Max region size for fast search
    static constexpr std::size_t MAX_FAST_SEARCH_RESULTS = 100;       ///< Result limit for fast search mode
};

} // namespace cheatengine
