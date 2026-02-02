#pragma once

#include <mach/mach.h>
#include <chrono>
#include <mutex>
#include <vector>

namespace cheatengine {

class ValueMonitor {
public:
    struct MonitoredAddress {
        mach_vm_address_t address{0};
        std::size_t value_size{0};
        std::vector<std::uint8_t> last_value;
        std::chrono::steady_clock::time_point last_update{};
    };

    struct ValueChange {
        mach_vm_address_t address{0};
        std::vector<std::uint8_t> old_value;
        std::vector<std::uint8_t> new_value;
        std::chrono::steady_clock::time_point timestamp{};
    };

    bool addAddress(mach_vm_address_t address, std::size_t size);
    void removeAddress(mach_vm_address_t address);
    std::vector<ValueChange> poll(task_t task);
    std::vector<MonitoredAddress> tracked();
    void clear();

private:
    static const std::size_t DEFAULT_MAX_MONITORED_ADDRESSES = 100;
    std::vector<MonitoredAddress> addresses_;
    std::mutex mutex_;
    std::size_t max_addresses_ = DEFAULT_MAX_MONITORED_ADDRESSES;
};

} // namespace cheatengine
