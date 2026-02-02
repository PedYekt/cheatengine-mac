#pragma once

#include <mach/mach.h>
#include <chrono>
#include <mutex>
#include <vector>

namespace cheatengine {

class MemoryWriter {
public:
    struct WriteOperation {
        mach_vm_address_t address{0};
        std::vector<std::uint8_t> old_value;
        std::vector<std::uint8_t> new_value;
        std::chrono::steady_clock::time_point timestamp{};
        bool success{false};
    };

    bool write(task_t task, mach_vm_address_t address, const std::vector<std::uint8_t>& data);
    bool canWrite(task_t task, mach_vm_address_t address, std::size_t size) const;
    std::vector<WriteOperation> history();

private:
    void recordOperation(WriteOperation op);
    static const std::size_t MAX_HISTORY_SIZE = 100;
    std::vector<WriteOperation> history_;
    std::mutex mutex_;
};

} // namespace cheatengine
