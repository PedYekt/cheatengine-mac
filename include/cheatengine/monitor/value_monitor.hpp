/**
 * @file value_monitor.hpp
 * @brief Real-time memory value monitoring and change detection
 * 
 * This file demonstrates how to implement real-time monitoring of memory
 * locations, providing educational insight into temporal locality, memory
 * access patterns, and change detection algorithms.
 * 
 * Educational Focus:
 * - Real-time memory monitoring techniques
 * - Change detection algorithms and optimization
 * - Thread-safe data structure design
 * - Temporal locality and memory access patterns
 * - Performance considerations for periodic operations
 */

#pragma once

#include <mach/mach.h>

#include <chrono>
#include <mutex>
#include <optional>
#include <vector>

namespace cheatengine {

/**
 * @brief Real-time memory value monitoring system
 * 
 * The ValueMonitor class demonstrates how to implement efficient real-time
 * monitoring of memory locations, showcasing change detection algorithms
 * and thread-safe design patterns for system programming.
 * 
 * Educational Concepts Demonstrated:
 * - Real-time memory monitoring and change detection
 * - Thread-safe data structure design with mutexes
 * - Temporal locality and memory access pattern analysis
 * - Efficient polling strategies for system resources
 * - Change tracking and historical data management
 * 
 * Performance Considerations:
 * - Minimizes memory reads through efficient polling
 * - Uses thread-safe operations for concurrent access
 * - Implements change detection to reduce noise
 * - Provides configurable monitoring intervals
 * 
 * Use Cases:
 * - Variable change tracking in running applications
 * - Real-time debugging and analysis
 * - Understanding program behavior and data flow
 * - Educational demonstration of memory access patterns
 */
class ValueMonitor {
public:
    /**
     * @brief Information about a monitored memory address
     * 
     * This structure captures all necessary information for tracking
     * changes at a specific memory location over time.
     */
    struct MonitoredAddress {
        mach_vm_address_t address{0};                           ///< Virtual address being monitored
        std::size_t value_size{0};                             ///< Size of value in bytes
        std::vector<std::uint8_t> last_value;                  ///< Last known value at this address
        std::chrono::steady_clock::time_point last_update{};   ///< When this address was last checked
    };

    /**
     * @brief Record of a detected value change
     * 
     * This structure captures comprehensive information about detected
     * changes, useful for analysis and educational purposes.
     */
    struct ValueChange {
        mach_vm_address_t address{0};                           ///< Address where change occurred
        std::vector<std::uint8_t> old_value;                   ///< Previous value
        std::vector<std::uint8_t> new_value;                   ///< New value after change
        std::chrono::steady_clock::time_point timestamp{};     ///< When change was detected
    };

    /**
     * @brief Add a memory address to the monitoring list
     * @param address Virtual address to monitor
     * @param size Size of value to monitor in bytes
     * @return true if address was added, false if limit was reached
     *
     * Demonstrates how to safely add addresses to a thread-safe monitoring
     * system. Shows proper initialization of monitoring state.
     *
     * Educational Note: This method shows how to set up monitoring for
     * different data types by specifying the appropriate size. It also
     * demonstrates resource limit enforcement to prevent excessive memory use.
     */
    bool addAddress(mach_vm_address_t address, std::size_t size);
    
    /**
     * @brief Remove a memory address from monitoring
     * @param address Virtual address to stop monitoring
     * 
     * Demonstrates safe removal from thread-safe data structures and
     * proper cleanup of monitoring resources.
     */
    void removeAddress(mach_vm_address_t address);
    
    /**
     * @brief Poll all monitored addresses for changes
     * @param task Mach task port for memory access
     * @return std::vector<ValueChange> List of detected changes since last poll
     * 
     * This method demonstrates efficient change detection algorithms and
     * shows how to implement periodic monitoring with minimal overhead.
     * 
     * Educational Concepts:
     * - Efficient polling strategies for system resources
     * - Change detection algorithms and optimization
     * - Batch processing for improved performance
     * - Error handling for memory access failures
     * 
     * Performance Features:
     * - Batches memory reads for efficiency
     * - Only reports actual changes to reduce noise
     * - Handles memory access errors gracefully
     * - Updates monitoring state atomically
     */
    std::vector<ValueChange> poll(task_t task);
    
    /**
     * @brief Get list of currently monitored addresses
     * @return std::vector<MonitoredAddress> Copy of current monitoring state
     *
     * Provides thread-safe access to the current monitoring configuration,
     * useful for status display and debugging.
     *
     * Educational Note: Returns a copy to ensure thread safety while
     * allowing inspection of the monitoring state.
     */
    std::vector<MonitoredAddress> tracked() const;

    /**
     * @brief Clear all monitored addresses
     *
     * Removes all addresses from the monitoring list in a thread-safe manner.
     * This is useful for cleanup operations or when switching to a different
     * monitoring configuration.
     *
     * Educational Note: Demonstrates safe cleanup of monitoring resources
     * and proper use of RAII principles for resource management.
     */
    void clear();

private:
    /// Default maximum number of addresses that can be monitored simultaneously
    /// Prevents excessive memory usage and system overhead
    static constexpr std::size_t DEFAULT_MAX_MONITORED_ADDRESSES = 100;

    std::vector<MonitoredAddress> addresses_;   ///< List of monitored addresses
    mutable std::mutex mutex_;                  ///< Thread safety for concurrent access
    std::size_t max_addresses_ = DEFAULT_MAX_MONITORED_ADDRESSES;  ///< Maximum allowed monitored addresses
};

} // namespace cheatengine
