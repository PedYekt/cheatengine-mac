/**
 * @file memory_writer.hpp
 * @brief Safe memory modification with comprehensive validation and logging
 */

#pragma once

#include <mach/mach.h>

#include <chrono>
#include <mutex>
#include <vector>

namespace cheatengine {

/**
 * @brief Safe memory modification with comprehensive validation and audit logging
 */
class MemoryWriter {
public:
    /**
     * @brief Record of a memory write operation attempt
     */
    struct WriteOperation {
        mach_vm_address_t address{0};                           ///< Target memory address
        std::vector<std::uint8_t> old_value;                   ///< Original value before write
        std::vector<std::uint8_t> new_value;                   ///< New value written to memory
        std::chrono::steady_clock::time_point timestamp{};     ///< When operation was attempted
        bool success{false};                                   ///< Whether write succeeded
    };

    /**
     * @brief Write data to a memory address with comprehensive validation
     * @param task Mach task port for the target process
     * @param address Target virtual address to write to
     * @param data Binary data to write to the address
     * @return true if write succeeded, false otherwise
     */
    bool write(task_t task, mach_vm_address_t address, const std::vector<std::uint8_t>& data);
    
    /**
     * @brief Check if a memory region can be written to
     * @param task Mach task port for the target process
     * @param address Starting address to check
     * @param size Size of region to validate
     * @return true if region has write permissions
     */
    bool canWrite(task_t task, mach_vm_address_t address, std::size_t size) const;
    
    /**
     * @brief Get complete history of write operations
     * @return std::vector<WriteOperation> Copy of all recorded operations
     */
    std::vector<WriteOperation> history() const;

private:
    /**
     * @brief Record a write operation in the audit log
     * @param operation WriteOperation to add to history
     */
    void recordOperation(WriteOperation operation);

    static constexpr std::size_t MAX_HISTORY_SIZE = 100;  ///< Maximum number of operations to keep in history

    std::vector<WriteOperation> history_;       ///< Complete audit log of write operations (limited to MAX_HISTORY_SIZE)
    mutable std::mutex mutex_;                  ///< Thread safety for concurrent access
};

} // namespace cheatengine
