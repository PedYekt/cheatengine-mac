#include "cheatengine/monitor/value_monitor.hpp"

#include <algorithm>
#include <mach/mach_vm.h>


namespace {
bool readValue(task_t task, mach_vm_address_t address, std::size_t size,
               std::vector<std::uint8_t>& buffer)
{
    buffer.resize(size);
    mach_vm_size_t out_size = 0;
    kern_return_t kr = mach_vm_read_overwrite(task,
                                              address,
                                              size,
                                              reinterpret_cast<mach_vm_address_t>(buffer.data()),
                                              &out_size);
    if (kr != KERN_SUCCESS || out_size != size) {
        buffer.clear();
        return false;
    }
    return true;
}
} // namespace


namespace cheatengine {

bool ValueMonitor::addAddress(mach_vm_address_t address, std::size_t size)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if we've reached the maximum number of monitored addresses
    if (addresses_.size() >= max_addresses_) {
        return false;
    }

    addresses_.push_back({address, size, {}, std::chrono::steady_clock::now()});
    return true;
}

void ValueMonitor::removeAddress(mach_vm_address_t address)
{
    std::lock_guard<std::mutex> lock(mutex_);
    addresses_.erase(std::remove_if(addresses_.begin(), addresses_.end(),
                                    [address](const MonitoredAddress& entry) { return entry.address == address; }),
                     addresses_.end());
}

std::vector<ValueMonitor::ValueChange> ValueMonitor::poll(task_t task)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ValueChange> changes;

    if (task == MACH_PORT_NULL) {
        return changes;
    }

    for (auto& entry : addresses_){
        std::vector<std::uint8_t> current;
        if (!readValue(task, entry.address, entry.value_size, current)) {
            continue;
        }

        if (entry.last_value.empty()) {
            entry.last_value = current;
            entry.last_update = std::chrono::steady_clock::now();
            continue;
        }

        if (current != entry.last_value) {
            ValueChange change;
            change.address = entry.address;
            change.old_value = entry.last_value;
            change.new_value = current;
            change.timestamp = std::chrono::steady_clock::now();
            changes.push_back(std::move(change));

            entry.last_value = std::move(current);
            entry.last_update = std::chrono::steady_clock::now();
        }
    }

    return changes;
}

std::vector<ValueMonitor::MonitoredAddress> ValueMonitor::tracked() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return addresses_;
}

void ValueMonitor::clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    addresses_.clear();
}

} // namespace cheatengine
