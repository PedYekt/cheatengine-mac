/**
 * @file value_monitor.hpp
 * @brief Real-time memory value monitoring and change detection
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
 */
class ValueMonitor {
public:
    /**
     * @brief Information about a monitored memory address
     */
    struct MonitoredAddress {
        mach_vm_address_t address{0};                           ///< Virtual address being monitored
        std::size_t value_size{0};                             ///< Size of value in bytes
        std::vector<std::uint8_t> last_value;                  ///< Last known value at this address
        std::chrono::steady_clock::time_point last_update{};   ///< When this address was last checked
    };

    /**
     * @brief Record of a detected value change
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
     */
    bool addAddress(mach_vm_address_t address, std::size_t size);
    
    /**
     * @brief Remove a memory address from monitoring
     * @param address Virtual address to stop monitoring
     */
    void removeAddress(mach_vm_address_t address);
    
    /**
     * @brief Poll all monitored addresses for changes
     * @param task Mach task port for memory access
     * @return std::vector<ValueChange> List of detected changes since last poll
     */
    std::vector<ValueChange> poll(task_t task);
    
    /**
     * @brief Get list of currently monitored addresses
     * @return std::vector<MonitoredAddress> Copy of current monitoring state
     */
    std::vector<MonitoredAddress> tracked() const;

    /**
     * @brief Clear all monitored addresses
     */
    void clear();

private:
    /** Default maximum number of monitored addresses. */
    static constexpr std::size_t DEFAULT_MAX_MONITORED_ADDRESSES = 100;

    std::vector<MonitoredAddress> addresses_;   ///< List of monitored addresses
    mutable std::mutex mutex_;                  ///< Thread safety for concurrent access
    std::size_t max_addresses_ = DEFAULT_MAX_MONITORED_ADDRESSES;  ///< Maximum allowed monitored addresses
};

} // namespace cheatengine
