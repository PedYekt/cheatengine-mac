/**
 * @file memory_scanner.hpp
 * @brief Memory enumeration and searching using Mach VM APIs
 */

#pragma once

#include "cheatengine/memory/memory_region.hpp"
#include "cheatengine/memory/value_types.hpp"

#include <mach/mach.h>

#include <vector>

namespace cheatengine {

/**
 * @brief Memory scanner for process introspection and value searching
 */
class MemoryScanner {
public:
    /**
     * @brief Result of a memory value search operation
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
     */
    std::vector<MemoryRegion> enumerate(task_t task) const;
    
    /**
     * @brief Search for a specific value in process memory
     * @param task Mach task port for the target process
     * @param value SearchValue to look for in memory
     * @return std::vector<SearchResult> List of addresses where value was found
     */
    std::vector<SearchResult> search(task_t task, const SearchValue& value) const;
    
    /**
     * @brief Read a chunk of memory from the target process
     * @param task Mach task port for the target process
     * @param address Starting virtual address to read from
     * @param size Number of bytes to read
     * @param buffer Output buffer to store the read data
     * @return true if read succeeded, false otherwise
     */
    bool readChunk(task_t task, mach_vm_address_t address, std::size_t size, std::vector<std::uint8_t>& buffer) const;
    
    // Display and formatting methods.
    
    /**
     * @brief Format memory regions for detailed display
     * @param regions List of memory regions to format
     * @return std::string Human-readable representation of memory layout
     */
    std::string formatRegions(const std::vector<MemoryRegion>& regions) const;
    
    /**
     * @brief Format search results for analysis
     * @param results List of search results to format
     * @return std::string Human-readable representation of search findings
     */
    std::string formatSearchResults(const std::vector<SearchResult>& results) const;
    
    // Advanced memory operations.
    
    /**
     * @brief Read a large memory range using optimized chunking
     * @param task Mach task port for the target process
     * @param start_address Starting address of the range
     * @param total_size Total size of the range to read
     * @param buffer Output buffer for the entire range
     * @return true if the entire range was read successfully
     */
    bool readMemoryRange(task_t task, mach_vm_address_t start_address, 
                        mach_vm_size_t total_size, std::vector<std::uint8_t>& buffer) const;
    
    // Enhanced search functionality.
    
    /**
     * @brief Search for a value within a specific memory region
     * @param task Mach task port for the target process
     * @param region Specific memory region to search within
     * @param value SearchValue to look for
     * @return std::vector<SearchResult> Matches found within the region
     */
    std::vector<SearchResult> searchInRegion(task_t task, const MemoryRegion& region, 
                                           const SearchValue& value) const;
    
    /**
     * @brief Search for multiple values simultaneously
     * @param task Mach task port for the target process
     * @param values List of SearchValues to look for
     * @return std::vector<SearchResult> All matches found for any value
     */
    std::vector<SearchResult> searchMultipleValues(task_t task, 
                                                  const std::vector<SearchValue>& values) const;
    
    /**
     * @brief Fast search that focuses on likely memory regions
     * @param task Mach task port for the target process
     * @param value SearchValue to look for
     * @return std::vector<SearchResult> Matches found in high-probability regions
     */
    std::vector<SearchResult> searchFast(task_t task, const SearchValue& value) const;
    
    // Search result management.
    
    /**
     * @brief Format a single search result with detailed analysis
     * @param result SearchResult to format
     * @param original_value Original SearchValue that was found
     * @return std::string Detailed analysis of the search result
     */
    std::string formatSearchResultDetailed(const SearchResult& result, const SearchValue& original_value) const;
    
private:
    /** Page-aligned reading size in bytes. */
    static constexpr std::size_t CHUNK_SIZE = 4096;

    /** Context bytes around search matches. */
    static constexpr std::size_t CONTEXT_BYTES = 16;

    /** Search performance and safety limits. */
    static constexpr std::size_t MAX_SEARCH_RESULTS = 1000;           ///< Limit results to prevent hanging
    static constexpr std::size_t MAX_REGION_SIZE_MB = 100;            ///< Skip regions larger than this in complete search
    static constexpr std::size_t MAX_FAST_SEARCH_REGION_SIZE_MB = 50; ///< Max region size for fast search
    static constexpr std::size_t MAX_FAST_SEARCH_RESULTS = 100;       ///< Result limit for fast search mode
};

} // namespace cheatengine
