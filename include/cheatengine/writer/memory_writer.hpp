/**
 * @file memory_writer.hpp
 * @brief Safe memory modification with comprehensive validation and logging
 * 
 * This file demonstrates how to implement safe memory modification operations
 * with proper permission validation, audit logging, and error handling.
 * 
 * Educational Focus:
 * - Memory protection validation and security boundaries
 * - Safe memory modification techniques using Mach APIs
 * - Audit logging for security-sensitive operations
 * - Permission checking and validation strategies
 * - Error handling for memory protection violations
 */

#pragma once

#include <mach/mach.h>

#include <chrono>
#include <mutex>
#include <vector>

namespace cheatengine {

/**
 * @brief Safe memory modification with comprehensive validation and audit logging
 * 
 * The MemoryWriter class demonstrates how to implement secure memory modification
 * operations that respect system security boundaries while providing educational
 * insight into memory protection mechanisms and safe programming practices.
 * 
 * Educational Concepts Demonstrated:
 * - Memory protection validation before dangerous operations
 * - Safe memory modification using mach_vm_write
 * - Comprehensive audit logging for security accountability
 * - Permission boundary checking and validation
 * - Error handling for memory protection violations
 * 
 * Security Features:
 * - Validates memory region permissions before writing
 * - Logs all write operations for audit purposes
 * - Preserves original values for potential rollback
 * - Provides detailed error information on failures
 * - Respects memory protection boundaries
 * 
 * Design Principles:
 * - Security-first: All operations validated before execution
 * - Audit trail: Complete logging of all modification attempts
 * - Educational: Detailed error messages explain security concepts
 * - Thread-safe: Safe for concurrent access from multiple threads
 * 
 * @warning This class performs potentially dangerous memory modifications.
 *          It should only be used on processes owned by the current user
 *          and for educational purposes.
 */
class MemoryWriter {
public:
    /**
     * @brief Record of a memory write operation attempt
     * 
     * This structure captures comprehensive information about memory write
     * operations for audit logging and educational analysis.
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
     * 
     * This method demonstrates safe memory modification with comprehensive
     * validation and error handling. It showcases how to respect memory
     * protection boundaries while providing educational feedback.
     * 
     * Educational Concepts:
     * - Memory protection validation using region information
     * - Safe memory modification with mach_vm_write
     * - Atomic operations for data consistency
     * - Comprehensive error handling and reporting
     * - Audit logging for security accountability
     * 
     * Security Features:
     * - Validates target region has write permissions
     * - Preserves original value for potential rollback
     * - Logs all write attempts regardless of success
     * - Provides detailed error information on failures
     * - Respects memory protection boundaries
     * 
     * @throws CheatEngineException on validation or system call failures
     */
    bool write(task_t task, mach_vm_address_t address, const std::vector<std::uint8_t>& data);
    
    /**
     * @brief Check if a memory region can be written to
     * @param task Mach task port for the target process
     * @param address Starting address to check
     * @param size Size of region to validate
     * @return true if region has write permissions
     * 
     * This method demonstrates how to validate memory permissions before
     * attempting dangerous operations. It shows proper use of memory region
     * information for security validation.
     * 
     * Educational Concepts:
     * - Memory region permission checking
     * - Proactive validation before dangerous operations
     * - Understanding memory protection flags
     * - Security boundary validation techniques
     * 
     * Implementation Details:
     * - Uses mach_vm_region to get protection information
     * - Validates entire requested range has write permissions
     * - Handles region boundaries and fragmentation
     * - Provides detailed error information on validation failures
     */
    bool canWrite(task_t task, mach_vm_address_t address, std::size_t size) const;
    
    /**
     * @brief Get complete history of write operations
     * @return std::vector<WriteOperation> Copy of all recorded operations
     * 
     * Provides access to the complete audit log of memory write operations,
     * useful for security analysis and educational review.
     * 
     * Educational Value:
     * - Shows comprehensive audit logging implementation
     * - Demonstrates security accountability practices
     * - Provides data for analyzing memory modification patterns
     * - Enables forensic analysis of program behavior
     * 
     * @note Returns a copy to ensure thread safety while allowing
     *       inspection of the operation history.
     */
    std::vector<WriteOperation> history() const;

private:
    /**
     * @brief Record a write operation in the audit log
     * @param operation WriteOperation to add to history
     *
     * Internal method for maintaining comprehensive audit logs of all
     * memory modification attempts, successful or failed.
     *
     * Educational Note: Implements a rolling window of recent operations
     * to prevent unbounded memory growth while maintaining audit trail.
     */
    void recordOperation(WriteOperation operation);

    static constexpr std::size_t MAX_HISTORY_SIZE = 100;  ///< Maximum number of operations to keep in history

    std::vector<WriteOperation> history_;       ///< Complete audit log of write operations (limited to MAX_HISTORY_SIZE)
    mutable std::mutex mutex_;                  ///< Thread safety for concurrent access
};

} // namespace cheatengine
