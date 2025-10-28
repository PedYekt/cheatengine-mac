#include "cheatengine/writer/memory_writer.hpp"

#include <mach/mach_init.h>
#include <mach/mach_vm.h>

namespace {

bool readBytes(task_t task,
    mach_vm_address_t address,
    std::size_t size,
    std::vector<std::uint8_t>& buffer)
{
    buffer.resize(size);

    mach_vm_size_t out_size = 0;
    const kern_return_t kr = mach_vm_read_overwrite(
        task,
        address,
        static_cast<mach_vm_size_t>(size),
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

bool MemoryWriter::write(task_t task,
    mach_vm_address_t address,
    const std::vector<std::uint8_t>& data)
{
    WriteOperation op;
    op.address = address;
    op.new_value = data;
    op.timestamp = std::chrono::steady_clock::now();
    op.success = false;

    if (task == MACH_PORT_NULL || data.empty()) {
        recordOperation(std::move(op));
        return false;
    }

    if (!canWrite(task, address, data.size())) {
        recordOperation(std::move(op));
        return false;
    }

    std::vector<std::uint8_t> previous_value;
    if (readBytes(task, address, data.size(), previous_value)) {
        op.old_value = previous_value;
    }

    const kern_return_t kr = mach_vm_write(
        task,
        address,
        reinterpret_cast<vm_offset_t>(const_cast<std::uint8_t*>(data.data())),
        static_cast<mach_msg_type_number_t>(data.size()));

    op.success = (kr == KERN_SUCCESS);

    recordOperation(std::move(op));
    return op.success;
}

bool MemoryWriter::canWrite(task_t task,
    mach_vm_address_t address,
    std::size_t size) const
{
    if (task == MACH_PORT_NULL || size == 0) {
        return false;
    }

    mach_vm_address_t region_address = address;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info {};
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    const kern_return_t kr = mach_vm_region(
        task,
        &region_address,
        &region_size,
        VM_REGION_BASIC_INFO_64,
        reinterpret_cast<vm_region_info_t>(&info),
        &info_count,
        &object_name);

    if (object_name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object_name);
    }

    if (kr != KERN_SUCCESS) {
        return false;
    }

    const mach_vm_address_t requested_end = address + static_cast<mach_vm_address_t>(size);
    const mach_vm_address_t region_end = region_address + region_size;

    if (requested_end < address) { // overflow check
        return false;
    }

    if (address < region_address || requested_end > region_end) {
        return false;
    }

    return (info.protection & VM_PROT_WRITE) != 0;
}

std::vector<MemoryWriter::WriteOperation> MemoryWriter::history() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return history_;
}

void MemoryWriter::recordOperation(WriteOperation operation)
{
    std::lock_guard<std::mutex> lock(mutex_);
    history_.push_back(std::move(operation));

    // Keep only the most recent MAX_HISTORY_SIZE operations
    // This prevents unbounded memory growth while maintaining audit trail
    if (history_.size() > MAX_HISTORY_SIZE) {
        history_.erase(history_.begin());
    }
}

} // namespace cheatengine
