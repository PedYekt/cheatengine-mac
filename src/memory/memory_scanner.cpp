#include "cheatengine/memory/memory_scanner.hpp"
#include "cheatengine/core/errors.hpp"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <mach/mach_vm.h>

namespace cheatengine {

std::vector<MemoryRegion> MemoryScanner::enumerate(task_t task) const
{
    std::vector<MemoryRegion> regions;

    if (task == MACH_PORT_NULL){
        return regions;
    }

    // Start from minimum address and iterate sequentially to ensure sorted order
    mach_vm_address_t address = MACH_VM_MIN_ADDRESS;
    mach_vm_size_t size = 0;
    natural_t depth = 0;

    while(true){
        vm_region_submap_info_data_64_t info{};
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;

        kern_return_t kr = mach_vm_region_recurse(
            task,
            &address,
            &size,
            &depth,
            reinterpret_cast<vm_region_recurse_info_t>(&info),
            &info_count);
        
        if (kr != KERN_SUCCESS){
            break;
        }

        if (info.is_submap){
            depth += 1;
            continue;
        }

        MemoryRegion region;
        region.start_address = address;
        region.size = size;
        region.protection = info.protection;
        region.is_shared = (info.share_mode != SM_PRIVATE);
        region.category = categorizeRegion(info, address);

        regions.push_back(region);

        address += size;
    }

    return regions;
}

std::vector<MemoryScanner::SearchResult> MemoryScanner::search(task_t task, const SearchValue& value) const
{
    std::vector<SearchResult> results;

    if (task == MACH_PORT_NULL) {
        return results;
    }

    const auto& needle = value.data();
    if (needle.empty()) {
        return results;
    }

    const mach_vm_size_t chunk_size = CHUNK_SIZE;
    const std::size_t context_bytes = CONTEXT_BYTES;
    const std::size_t max_results = MAX_SEARCH_RESULTS;

    const auto regions = enumerate(task);
    std::cout << "Scanning " << regions.size() << " memory regions..." << std::endl;
    
    size_t regions_processed = 0;
    size_t total_bytes_scanned = 0;
    
    for (const auto& region : regions) {
        if (!region.flags().readable) {
            continue;
        }
        
        // Skip very large regions that might cause hangs
        const std::size_t max_region_bytes = MAX_REGION_SIZE_MB * 1024 * 1024;
        if (region.size > max_region_bytes) {
            std::cout << "Skipping large region: " << region.category
                      << " (" << (region.size / (1024 * 1024)) << " MB)" << std::endl;
            continue;
        }
        
        // Progress reporting
        if (regions_processed % 10 == 0) {
            std::cout << "Processed " << regions_processed << "/" << regions.size() 
                      << " regions, found " << results.size() << " matches..." << std::endl;
        }

        mach_vm_size_t offset = 0;
        while (offset < region.size) {
            // Check if we've found enough results
            if (results.size() >= max_results) {
                std::cout << "Reached maximum results limit (" << max_results << "), stopping search." << std::endl;
                return results;
            }
            
            mach_vm_size_t bytes_to_read =
                std::min(chunk_size, region.size - offset);

            std::vector<std::uint8_t> buffer;
            if (!readChunk(task, region.start_address + offset, bytes_to_read, buffer)) {
                offset += bytes_to_read;
                continue;
            }
            
            total_bytes_scanned += buffer.size();

            auto it = std::search(buffer.begin(), buffer.end(),
                                  needle.begin(), needle.end());

            while (it != buffer.end()) {
                const auto match_index =
                    static_cast<std::size_t>(std::distance(buffer.begin(), it));

                const mach_vm_address_t match_address =
                    region.start_address + offset + match_index;

                const std::size_t context_start =
                    (match_index > context_bytes)
                        ? match_index - context_bytes
                        : 0;

                const std::size_t context_end =
                    std::min(match_index + needle.size() + context_bytes,
                             buffer.size());

                using difference_type = std::vector<std::uint8_t>::difference_type;
                auto start_it = buffer.begin();
                std::advance(start_it, static_cast<difference_type>(context_start));
                auto end_it = buffer.begin();
                std::advance(end_it, static_cast<difference_type>(context_end));

                std::vector<std::uint8_t> context(start_it, end_it);

                SearchResult result;
                result.address = match_address;
                result.context = std::move(context);
                result.value_size = needle.size();
                results.push_back(std::move(result));

                it = std::search(it + 1, buffer.end(),
                                 needle.begin(), needle.end());
                                 
                // Limit results per region to prevent hanging
                if (results.size() >= max_results) {
                    break;
                }
            }

            if (region.size - offset <= chunk_size) {
                break;
            }

            const mach_vm_size_t advance =
                chunk_size > needle.size()
                    ? chunk_size - static_cast<mach_vm_size_t>(needle.size() - 1)
                    : chunk_size;

            offset += advance;
        }
        
        regions_processed++;
    }
    
    std::cout << "Search complete! Scanned " << total_bytes_scanned << " bytes in " 
              << regions_processed << " regions." << std::endl;

    return results;
}

bool MemoryScanner::readChunk(task_t task,
    mach_vm_address_t address,
    std::size_t size,
    std::vector<std::uint8_t>& buffer) const
{
    if (task == MACH_PORT_NULL || size == 0) {
        buffer.clear();
        return false;
    }

    buffer.resize(size);

    mach_vm_size_t out_size = 0;

    kern_return_t kr = mach_vm_read_overwrite(
        task,
        address,
        static_cast<mach_vm_size_t>(size),
        reinterpret_cast<mach_vm_address_t>(buffer.data()),
        &out_size);

    if (kr != KERN_SUCCESS || out_size == 0) {
        buffer.clear();
        return false;
    }

    if (out_size < size) {
        buffer.resize(static_cast<std::size_t>(out_size));
    }

    return true;
}

bool MemoryScanner::readMemoryRange(task_t task, mach_vm_address_t start_address, 
                                   mach_vm_size_t total_size, std::vector<std::uint8_t>& buffer) const
{
    if (task == MACH_PORT_NULL || total_size == 0) {
        buffer.clear();
        return false;
    }

    buffer.clear();
    buffer.reserve(static_cast<std::size_t>(total_size));

    mach_vm_address_t current_address = start_address;
    mach_vm_size_t remaining_size = total_size;

    while (remaining_size > 0) {
        const mach_vm_size_t chunk_size = std::min(static_cast<mach_vm_size_t>(CHUNK_SIZE), remaining_size);
        
        std::vector<std::uint8_t> chunk_buffer;
        if (!readChunk(task, current_address, static_cast<std::size_t>(chunk_size), chunk_buffer)) {
            // If we can't read this chunk, try to continue with the next one
            // Fill with zeros for the failed chunk
            chunk_buffer.resize(static_cast<std::size_t>(chunk_size), 0);
        }

        buffer.insert(buffer.end(), chunk_buffer.begin(), chunk_buffer.end());
        
        current_address += chunk_size;
        remaining_size -= chunk_size;
    }

    return !buffer.empty();
}

std::vector<MemoryScanner::SearchResult> MemoryScanner::searchInRegion(task_t task, 
                                                                       const MemoryRegion& region, 
                                                                       const SearchValue& value) const
{
    std::vector<SearchResult> results;

    if (task == MACH_PORT_NULL || !region.flags().readable) {
        return results;
    }

    const auto& needle = value.data();
    if (needle.empty()) {
        return results;
    }

    mach_vm_size_t offset = 0;
    while (offset < region.size) {
        mach_vm_size_t bytes_to_read = std::min(static_cast<mach_vm_size_t>(CHUNK_SIZE), region.size - offset);

        std::vector<std::uint8_t> buffer;
        if (!readChunk(task, region.start_address + offset, static_cast<std::size_t>(bytes_to_read), buffer)) {
            offset += bytes_to_read;
            continue;
        }

        auto it = std::search(buffer.begin(), buffer.end(), needle.begin(), needle.end());

        while (it != buffer.end()) {
            const auto match_index = static_cast<std::size_t>(std::distance(buffer.begin(), it));
            const mach_vm_address_t match_address = region.start_address + offset + match_index;

            const std::size_t context_start = (match_index > CONTEXT_BYTES) ? match_index - CONTEXT_BYTES : 0;
            const std::size_t context_end = std::min(match_index + needle.size() + CONTEXT_BYTES, buffer.size());

            using difference_type = std::vector<std::uint8_t>::difference_type;
            auto start_it = buffer.begin();
            std::advance(start_it, static_cast<difference_type>(context_start));
            auto end_it = buffer.begin();
            std::advance(end_it, static_cast<difference_type>(context_end));

            std::vector<std::uint8_t> context(start_it, end_it);

            SearchResult result;
            result.address = match_address;
            result.context = std::move(context);
            result.value_size = needle.size();
            results.push_back(std::move(result));

            it = std::search(it + 1, buffer.end(), needle.begin(), needle.end());
        }

        if (region.size - offset <= static_cast<mach_vm_size_t>(CHUNK_SIZE)) {
            break;
        }

        const mach_vm_size_t advance = (CHUNK_SIZE > needle.size()) 
            ? static_cast<mach_vm_size_t>(CHUNK_SIZE) - static_cast<mach_vm_size_t>(needle.size() - 1)
            : static_cast<mach_vm_size_t>(CHUNK_SIZE);

        offset += advance;
    }

    return results;
}

std::vector<MemoryScanner::SearchResult> MemoryScanner::searchMultipleValues(task_t task, 
                                                                             const std::vector<SearchValue>& values) const
{
    std::vector<SearchResult> all_results;

    for (const auto& value : values) {
        auto results = search(task, value);
        all_results.insert(all_results.end(), results.begin(), results.end());
    }

    // Sort results by address for better organization
    std::sort(all_results.begin(), all_results.end(), 
              [](const SearchResult& a, const SearchResult& b) {
                  return a.address < b.address;
              });

    return all_results;
}

std::vector<MemoryScanner::SearchResult> MemoryScanner::searchFast(task_t task, const SearchValue& value) const
{
    std::vector<SearchResult> results;

    if (task == MACH_PORT_NULL) {
        return results;
    }

    const auto& needle = value.data();
    if (needle.empty()) {
        return results;
    }

    const auto regions = enumerate(task);
    std::cout << "Fast search: focusing on STACK, HEAP, and DATA regions..." << std::endl;
    
    size_t regions_searched = 0;
    
    for (const auto& region : regions) {
        if (!region.flags().readable) {
            continue;
        }
        
        // Only search likely regions for user data (case-insensitive)
        std::string category_lower = region.category;
        std::transform(category_lower.begin(), category_lower.end(), category_lower.begin(), ::tolower);
        
        if (category_lower != "stack" && 
            category_lower != "heap" && 
            category_lower != "data" &&
            category_lower != "unknown") {
            continue;
        }
        
        // Skip very large regions
        const std::size_t max_fast_region_bytes = MAX_FAST_SEARCH_REGION_SIZE_MB * 1024 * 1024;
        if (region.size > max_fast_region_bytes) {
            continue;
        }
        
        std::cout << "Searching " << region.category << " region (" 
                  << (region.size / 1024) << " KB)..." << std::endl;
        
        auto region_results = searchInRegion(task, region, value);
        results.insert(results.end(), region_results.begin(), region_results.end());
        
        regions_searched++;
        
        if (region_results.size() > 0) {
            std::cout << "Found " << region_results.size() << " matches in " 
                      << region.category << " region" << std::endl;
        }
        
        // Limit total results
        if (results.size() >= MAX_FAST_SEARCH_RESULTS) {
            std::cout << "Found enough matches, stopping search." << std::endl;
            break;
        }
    }
    
    std::cout << "Fast search complete! Searched " << regions_searched 
              << " regions, found " << results.size() << " matches." << std::endl;

    return results;
}

std::string MemoryScanner::formatRegions(const std::vector<MemoryRegion>& regions) const
{
    std::ostringstream oss;
    
    oss << "Memory Regions (" << regions.size() << " total):\n";
    oss << "Address Range                Size        Prot  Category   Shared\n";
    oss << "----------------------------------------------------------------\n";
    
    for (const auto& region : regions) {
        oss << std::hex << std::uppercase;
        oss << "0x" << std::setfill('0') << std::setw(16) << region.start_address;
        oss << "-0x" << std::setfill('0') << std::setw(16) << region.endAddress();
        oss << std::dec << std::nouppercase;
        
        oss << "  " << std::setw(10) << region.sizeString();
        oss << "  " << std::setw(4) << region.flags().toString();
        oss << "  " << std::setw(9) << region.category;
        oss << "  " << (region.is_shared ? "Yes" : "No");
        oss << "\n";
    }
    
    return oss.str();
}

std::string MemoryScanner::formatSearchResults(const std::vector<SearchResult>& results) const
{
    std::ostringstream oss;
    
    oss << "Search Results (" << results.size() << " matches found):\n";
    oss << "Address            Value Size  Context\n";
    oss << "----------------------------------------\n";
    
    for (const auto& result : results) {
        oss << std::hex << std::uppercase;
        oss << "0x" << std::setfill('0') << std::setw(16) << result.address;
        oss << std::dec << std::nouppercase;
        
        oss << "  " << std::setw(10) << result.value_size << " bytes";
        
        // Show context as hex bytes
        oss << "  ";
        for (std::size_t i = 0; i < std::min(result.context.size(), std::size_t{32}); ++i) {
            oss << std::hex << std::setfill('0') << std::setw(2) 
                << static_cast<unsigned>(result.context[i]) << " ";
        }
        if (result.context.size() > 32) {
            oss << "...";
        }
        oss << std::dec;
        oss << "\n";
    }
    
    return oss.str();
}

std::string MemoryScanner::formatSearchResultDetailed(const SearchResult& result, const SearchValue& original_value) const
{
    std::ostringstream oss;
    
    oss << "Match found at address: 0x" << std::hex << std::uppercase 
        << std::setfill('0') << std::setw(16) << result.address << std::dec << std::nouppercase << "\n";
    
    oss << "Value size: " << result.value_size << " bytes\n";
    
    // Show the original search value
    oss << "Search value: ";
    switch (original_value.type()) {
        case ValueType::INT32:
            oss << original_value.toInt32() << " (int32)";
            break;
        case ValueType::INT64:
            oss << original_value.toInt64() << " (int64)";
            break;
        case ValueType::FLOAT32:
            oss << original_value.toFloat32() << " (float32)";
            break;
        case ValueType::FLOAT64:
            oss << original_value.toFloat64() << " (float64)";
            break;
        case ValueType::BYTES:
            oss << "raw bytes";
            break;
    }
    oss << "\n";
    
    // Show context with highlighting
    oss << "Memory context:\n";
    const std::size_t match_start = (result.context.size() > CONTEXT_BYTES + result.value_size) 
        ? CONTEXT_BYTES : 0;
    
    for (std::size_t i = 0; i < result.context.size(); ++i) {
        if (i == match_start) oss << "[";
        oss << std::hex << std::setfill('0') << std::setw(2) 
            << static_cast<unsigned>(result.context[i]);
        if (i == match_start + result.value_size - 1) oss << "]";
        oss << " ";
        if ((i + 1) % 16 == 0) oss << "\n";
    }
    oss << std::dec << "\n";
    
    return oss.str();
}

} // namespace cheatengine
