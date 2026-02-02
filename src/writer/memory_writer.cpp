#include "cheatengine/writer/memory_writer.hpp"

#include <mach/mach_init.h>
#include <mach/mach_vm.h>

namespace {

bool readBytes(task_t task, mach_vm_address_t address, std::size_t size, std::vector<std::uint8_t>& buffer)
{
    buffer.resize(size);
    mach_vm_size_t out_size = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, address, size,
        reinterpret_cast<mach_vm_address_t>(buffer.data()), &out_size);

    if (kr != KERN_SUCCESS || out_size != size) {
        buffer.clear();
        return false;
    }
    return true;
}

} // namespace

namespace cheatengine {

bool MemoryWriter::write(task_t task, mach_vm_address_t address, const std::vector<std::uint8_t>& data)
{
    WriteOperation op;
    op.address = address;
    op.new_value = data;
    op.timestamp = std::chrono::steady_clock::now();
    op.success = false;

    if (task == MACH_PORT_NULL || data.empty() || !canWrite(task, address, data.size())) {
        recordOperation(op);
        return false;
    }

    std::vector<std::uint8_t> prev;
    if (readBytes(task, address, data.size(), prev)) {
        op.old_value = prev;
    }

    kern_return_t kr = mach_vm_write(task, address,
        reinterpret_cast<vm_offset_t>(const_cast<std::uint8_t*>(data.data())),
        static_cast<mach_msg_type_number_t>(data.size()));

    op.success = (kr == KERN_SUCCESS);
    recordOperation(op);
    return op.success;
}

bool MemoryWriter::canWrite(task_t task, mach_vm_address_t address, std::size_t size) const
{
    if (task == MACH_PORT_NULL || size == 0) return false;

    mach_vm_address_t region_addr = address;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info{};
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = mach_vm_region(task, &region_addr, &region_size,
        VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_t>(&info),
        &info_count, &object_name);

    if (object_name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), object_name);
    }

    if (kr != KERN_SUCCESS) return false;

    mach_vm_address_t req_end = address + size;
    if (req_end < address) return false;
    if (address < region_addr || req_end > region_addr + region_size) return false;

    return (info.protection & VM_PROT_WRITE) != 0;
}

std::vector<MemoryWriter::WriteOperation> MemoryWriter::history()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return history_;
}

void MemoryWriter::recordOperation(WriteOperation op)
{
    std::lock_guard<std::mutex> lock(mutex_);
    history_.push_back(op);
    if (history_.size() > MAX_HISTORY_SIZE) {
        history_.erase(history_.begin());
    }
}

} // namespace cheatengine
