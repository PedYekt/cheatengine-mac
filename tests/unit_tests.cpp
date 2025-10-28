#include "cheatengine/memory/memory_region.hpp"
#include "cheatengine/memory/memory_scanner.hpp"
#include "cheatengine/memory/value_types.hpp"
#include "cheatengine/monitor/value_monitor.hpp"
#include "cheatengine/writer/memory_writer.hpp"
#include "cheatengine/process/process_manager.hpp"
#include "cheatengine/process/security_manager.hpp"
#include "cheatengine/core/errors.hpp"

#include <cmath>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <memory>
#include <algorithm>
#include <unistd.h>
#include <limits>

namespace {

using cheatengine::ProtectionFlags;
using cheatengine::categorizeRegion;
using cheatengine::SearchValue;
using cheatengine::ValueMonitor;
using cheatengine::MemoryWriter;
using cheatengine::MemoryScanner;
using cheatengine::ProcessManager;
using cheatengine::SecurityManager;
using cheatengine::CheatEngineException;

#define EXPECT_TRUE(expr)                                                                 \
    do {                                                                                  \
        if (!(expr)) {                                                                    \
            std::cerr << __FILE__ << ":" << __LINE__ << " EXPECT_TRUE failed: " #expr     \
                      << std::endl;                                                      \
            return false;                                                                 \
        }                                                                                 \
    } while (0)

#define EXPECT_EQ(lhs, rhs)                                                               \
    do {                                                                                  \
        if (!((lhs) == (rhs))) {                                                          \
            std::cerr << __FILE__ << ":" << __LINE__ << " EXPECT_EQ failed: "             \
                      << #lhs << " == " << #rhs << std::endl;                             \
            return false;                                                                 \
        }                                                                                 \
    } while (0)

#define EXPECT_NEAR(lhs, rhs, tol)                                                        \
    do {                                                                                  \
        auto lhs_eval = static_cast<double>(lhs);                                         \
        auto rhs_eval = static_cast<double>(rhs);                                         \
        auto diff = std::fabs(lhs_eval - rhs_eval);                                       \
        if (diff > (tol)) {                                                               \
            std::cerr << __FILE__ << ":" << __LINE__ << " EXPECT_NEAR failed: "           \
                      << #lhs << " ~= " << #rhs << " (|diff| = " << diff << ")"           \
                      << std::endl;                                                      \
            return false;                                                                 \
        }                                                                                 \
    } while (0)

bool test_search_value_integer()
{
    const std::int32_t value = 0x1234ABCD;
    auto search_value = SearchValue::fromInt32(value);

    EXPECT_EQ(search_value.type(), cheatengine::ValueType::INT32);
    EXPECT_EQ(search_value.data().size(), sizeof(std::int32_t));

    std::int32_t decoded = 0;
    std::memcpy(&decoded, search_value.data().data(), sizeof(decoded));
    EXPECT_EQ(decoded, value);

    const std::int64_t value64 = 0x1234567890ABCDEFull;
    auto search_value64 = SearchValue::fromInt64(value64);

    EXPECT_EQ(search_value64.type(), cheatengine::ValueType::INT64);
    EXPECT_EQ(search_value64.data().size(), sizeof(std::int64_t));

    std::int64_t decoded64 = 0;
    std::memcpy(&decoded64, search_value64.data().data(), sizeof(decoded64));
    EXPECT_EQ(decoded64, value64);

    return true;
}

bool test_search_value_float()
{
    const float fvalue = 3.1415926f;
    auto search_value = SearchValue::fromFloat32(fvalue);
    EXPECT_EQ(search_value.type(), cheatengine::ValueType::FLOAT32);
    EXPECT_EQ(search_value.data().size(), sizeof(float));

    float decoded = 0.0f;
    std::memcpy(&decoded, search_value.data().data(), sizeof(decoded));
    EXPECT_NEAR(decoded, fvalue, 1e-6);

    const double dvalue = 2.718281828459045;
    auto search_value64 = SearchValue::fromFloat64(dvalue);
    EXPECT_EQ(search_value64.type(), cheatengine::ValueType::FLOAT64);
    EXPECT_EQ(search_value64.data().size(), sizeof(double));

    double decoded64 = 0.0;
    std::memcpy(&decoded64, search_value64.data().data(), sizeof(decoded64));
    EXPECT_NEAR(decoded64, dvalue, 1e-12);

    const std::vector<std::uint8_t> bytes = {0xDE, 0xAD, 0xBE, 0xEF};
    auto from_bytes = SearchValue::fromBytes(bytes);
    EXPECT_EQ(from_bytes.type(), cheatengine::ValueType::BYTES);
    EXPECT_EQ(from_bytes.data(), bytes);

    return true;
}

bool test_protection_flags()
{
    auto flags = ProtectionFlags::fromNative(VM_PROT_READ | VM_PROT_EXECUTE);
    EXPECT_TRUE(flags.readable);
    EXPECT_TRUE(flags.executable);
    EXPECT_TRUE(!flags.writable);
    EXPECT_EQ(flags.toString(), std::string("r-x"));

    flags = ProtectionFlags::fromNative(VM_PROT_NONE);
    EXPECT_TRUE(!flags.readable);
    EXPECT_TRUE(!flags.writable);
    EXPECT_TRUE(!flags.executable);
    EXPECT_EQ(flags.toString(), std::string("---"));

    return true;
}

bool test_region_categorization()
{
    vm_region_submap_info_data_64_t info{};
    info.user_tag = VM_MEMORY_STACK;
    auto category = categorizeRegion(info, 0);
    EXPECT_EQ(category, std::string("Stack"));

    info = {};
    info.protection = VM_PROT_READ | VM_PROT_EXECUTE;
    category = categorizeRegion(info, 0);
    EXPECT_EQ(category, std::string("Code"));

    info = {};
    info.user_tag = VM_MEMORY_MALLOC;
    info.protection = VM_PROT_READ | VM_PROT_WRITE;
    category = categorizeRegion(info, 0);
    EXPECT_EQ(category, std::string("Heap"));

    info = {};
    info.share_mode = SM_SHARED;
    category = categorizeRegion(info, 0);
    EXPECT_EQ(category, std::string("Shared"));

    info = {};
    category = categorizeRegion(info, 0);
    EXPECT_EQ(category, std::string("Data"));

    return true;
}

bool test_value_monitor_address_management()
{
    ValueMonitor monitor;
    
    // Test adding addresses
    monitor.addAddress(0x1000, 4);
    monitor.addAddress(0x2000, 8);
    
    auto tracked = monitor.tracked();
    EXPECT_EQ(tracked.size(), 2);
    EXPECT_EQ(tracked[0].address, 0x1000);
    EXPECT_EQ(tracked[0].value_size, 4);
    EXPECT_EQ(tracked[1].address, 0x2000);
    EXPECT_EQ(tracked[1].value_size, 8);
    
    // Test removing addresses
    monitor.removeAddress(0x1000);
    tracked = monitor.tracked();
    EXPECT_EQ(tracked.size(), 1);
    EXPECT_EQ(tracked[0].address, 0x2000);
    
    // Test removing non-existent address (should not crash)
    monitor.removeAddress(0x9999);
    tracked = monitor.tracked();
    EXPECT_EQ(tracked.size(), 1);
    
    return true;
}

bool test_value_monitor_invalid_task()
{
    ValueMonitor monitor;
    monitor.addAddress(0x1000, 4);
    
    // Test with invalid task (should return empty changes)
    auto changes = monitor.poll(MACH_PORT_NULL);
    EXPECT_EQ(changes.size(), 0);
    
    return true;
}

bool test_memory_writer_invalid_parameters()
{
    MemoryWriter writer;
    
    // Test with invalid task
    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    bool result = writer.write(MACH_PORT_NULL, 0x1000, data);
    EXPECT_TRUE(!result);
    
    // Test with empty data
    std::vector<std::uint8_t> empty_data;
    result = writer.write(mach_task_self(), 0x1000, empty_data);
    EXPECT_TRUE(!result);
    
    // Test canWrite with invalid parameters
    EXPECT_TRUE(!writer.canWrite(MACH_PORT_NULL, 0x1000, 4));
    EXPECT_TRUE(!writer.canWrite(mach_task_self(), 0x1000, 0));
    
    return true;
}

bool test_memory_writer_history_tracking()
{
    MemoryWriter writer;
    
    // Initially should have no history
    auto history = writer.history();
    EXPECT_EQ(history.size(), 0);
    
    // Attempt a write operation (will fail but should be recorded)
    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    writer.write(MACH_PORT_NULL, 0x1000, data);
    
    // Check that operation was recorded
    history = writer.history();
    EXPECT_EQ(history.size(), 1);
    EXPECT_EQ(history[0].address, 0x1000);
    EXPECT_EQ(history[0].new_value, data);
    EXPECT_TRUE(!history[0].success);
    
    return true;
}

// Mock Mach API for isolated testing
class MockMachAPI {
public:
    static std::vector<std::uint8_t> mock_memory;
    static bool should_fail_read;
    static bool should_fail_write;
    
    static kern_return_t mock_vm_read(task_t task, mach_vm_address_t address, 
                                     mach_vm_size_t size, vm_offset_t* data, 
                                     mach_msg_type_number_t* data_count) {
        if (should_fail_read || task == MACH_PORT_NULL) {
            return KERN_FAILURE;
        }
        
        // Simulate reading from mock memory
        if (address < mock_memory.size() && address + size <= mock_memory.size()) {
            *data_count = static_cast<mach_msg_type_number_t>(size);
            return KERN_SUCCESS;
        }
        return KERN_INVALID_ADDRESS;
    }
    
    static kern_return_t mock_vm_write(task_t task, mach_vm_address_t address,
                                      vm_offset_t data, mach_msg_type_number_t data_count) {
        if (should_fail_write || task == MACH_PORT_NULL) {
            return KERN_FAILURE;
        }
        
        // Simulate writing to mock memory
        if (address < mock_memory.size() && address + data_count <= mock_memory.size()) {
            return KERN_SUCCESS;
        }
        return KERN_INVALID_ADDRESS;
    }
    
    static void reset() {
        mock_memory.clear();
        should_fail_read = false;
        should_fail_write = false;
    }
};

std::vector<std::uint8_t> MockMachAPI::mock_memory;
bool MockMachAPI::should_fail_read = false;
bool MockMachAPI::should_fail_write = false;

bool test_search_value_edge_cases()
{
    // Test zero values
    auto zero_int = SearchValue::fromInt32(0);
    EXPECT_EQ(zero_int.type(), cheatengine::ValueType::INT32);
    
    std::int32_t decoded = 1; // Non-zero to verify it gets overwritten
    std::memcpy(&decoded, zero_int.data().data(), sizeof(decoded));
    EXPECT_EQ(decoded, 0);
    
    // Test negative values
    auto neg_int = SearchValue::fromInt32(-12345);
    std::memcpy(&decoded, neg_int.data().data(), sizeof(decoded));
    EXPECT_EQ(decoded, -12345);
    
    // Test maximum values
    auto max_int = SearchValue::fromInt32(std::numeric_limits<std::int32_t>::max());
    std::memcpy(&decoded, max_int.data().data(), sizeof(decoded));
    EXPECT_EQ(decoded, std::numeric_limits<std::int32_t>::max());
    
    // Test minimum values
    auto min_int = SearchValue::fromInt32(std::numeric_limits<std::int32_t>::min());
    std::memcpy(&decoded, min_int.data().data(), sizeof(decoded));
    EXPECT_EQ(decoded, std::numeric_limits<std::int32_t>::min());
    
    return true;
}

bool test_search_value_special_floats()
{
    // Test NaN
    auto nan_val = SearchValue::fromFloat32(std::numeric_limits<float>::quiet_NaN());
    EXPECT_EQ(nan_val.type(), cheatengine::ValueType::FLOAT32);
    
    float decoded_nan;
    std::memcpy(&decoded_nan, nan_val.data().data(), sizeof(decoded_nan));
    EXPECT_TRUE(std::isnan(decoded_nan));
    
    // Test infinity
    auto inf_val = SearchValue::fromFloat32(std::numeric_limits<float>::infinity());
    float decoded_inf;
    std::memcpy(&decoded_inf, inf_val.data().data(), sizeof(decoded_inf));
    EXPECT_TRUE(std::isinf(decoded_inf));
    
    // Test negative infinity
    auto neg_inf_val = SearchValue::fromFloat32(-std::numeric_limits<float>::infinity());
    float decoded_neg_inf;
    std::memcpy(&decoded_neg_inf, neg_inf_val.data().data(), sizeof(decoded_neg_inf));
    EXPECT_TRUE(std::isinf(decoded_neg_inf) && decoded_neg_inf < 0);
    
    return true;
}

bool test_memory_scanner_search_results()
{
    MemoryScanner scanner;
    
    // Test search result structure
    MemoryScanner::SearchResult result;
    result.address = 0x1000;
    result.value_size = 4;
    result.context = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    EXPECT_EQ(result.address, 0x1000);
    EXPECT_EQ(result.value_size, 4);
    EXPECT_EQ(result.context.size(), 8);
    
    return true;
}

bool test_memory_scanner_chunk_reading()
{
    MemoryScanner scanner;
    std::vector<std::uint8_t> buffer;
    
    // Test reading with invalid task
    bool result = scanner.readChunk(MACH_PORT_NULL, 0x1000, 100, buffer);
    EXPECT_TRUE(!result);
    
    // Test reading with zero size
    result = scanner.readChunk(mach_task_self(), 0x1000, 0, buffer);
    EXPECT_TRUE(!result);
    
    return true;
}

bool test_process_manager_error_handling()
{
    ProcessManager manager;
    
    // Test invalid PID
    bool result = manager.attachToProcess(-1);
    EXPECT_TRUE(!result);
    EXPECT_EQ(manager.getLastError(), ProcessManager::AttachmentError::INVALID_PID);
    
    // Test non-existent PID
    result = manager.attachToProcess(999999);
    EXPECT_TRUE(!result);
    // Should be either PROCESS_NOT_FOUND or PERMISSION_DENIED
    auto error = manager.getLastError();
    EXPECT_TRUE(error == ProcessManager::AttachmentError::PROCESS_NOT_FOUND ||
                error == ProcessManager::AttachmentError::PERMISSION_DENIED);
    
    // Test error description
    auto desc = manager.getErrorDescription(ProcessManager::AttachmentError::INVALID_PID);
    EXPECT_TRUE(!desc.empty());
    
    return true;
}

bool test_process_manager_state_management()
{
    ProcessManager manager;
    
    // Initial state should be detached
    EXPECT_EQ(manager.getCurrentState(), ProcessManager::ProcessState::DETACHED);
    
    auto info = manager.getCurrentProcess();
    EXPECT_EQ(info.pid, 0);
    EXPECT_TRUE(!info.is_attached);
    EXPECT_EQ(info.state, ProcessManager::ProcessState::DETACHED);
    
    // Test detaching when not attached (should not crash)
    manager.detachFromProcess();
    EXPECT_EQ(manager.getCurrentState(), ProcessManager::ProcessState::DETACHED);
    
    return true;
}

bool test_process_manager_ownership_validation()
{
    ProcessManager manager;
    
    // Test with current process (should be owned by us)
    pid_t current_pid = getpid();
    bool owned = manager.validateProcessOwnership(current_pid);
    EXPECT_TRUE(owned);
    
    // Test with invalid PID
    owned = manager.validateProcessOwnership(-1);
    EXPECT_TRUE(!owned);
    
    return true;
}

bool test_security_manager_system_process_detection()
{
    SecurityManager security;
    
    // Test with kernel_task (PID 0) - should be system process
    bool is_system = security.isSystemProcess(0);
    EXPECT_TRUE(is_system);
    
    // Test with launchd (PID 1) - should be system process
    is_system = security.isSystemProcess(1);
    EXPECT_TRUE(is_system);
    
    // Test with current process - should not be system process
    is_system = security.isSystemProcess(getpid());
    EXPECT_TRUE(!is_system);
    
    return true;
}

bool test_security_manager_access_evaluation()
{
    SecurityManager security;
    
    // Test access evaluation for current process
    auto access_info = security.evaluateProcessAccess(getpid());
    EXPECT_TRUE(!access_info.restriction_reason.empty() || 
                access_info.level != SecurityManager::AccessLevel::NO_ACCESS);
    
    // Test access evaluation for system process
    access_info = security.evaluateProcessAccess(0);
    EXPECT_EQ(access_info.level, SecurityManager::AccessLevel::NO_ACCESS);
    EXPECT_TRUE(!access_info.restriction_reason.empty());
    
    return true;
}

bool test_cheat_engine_exception_handling()
{
    // Test basic exception creation
    CheatEngineException ex(CheatEngineException::ErrorType::PROCESS_ACCESS, 
                           "Test error message");
    EXPECT_EQ(ex.type(), CheatEngineException::ErrorType::PROCESS_ACCESS);
    EXPECT_TRUE(std::string(ex.what()).find("Test error message") != std::string::npos);
    
    // Test exception with system error
    CheatEngineException ex_with_errno(CheatEngineException::ErrorType::MEMORY_OPERATION,
                                      "Memory error", KERN_INVALID_ADDRESS);
    EXPECT_EQ(ex_with_errno.systemError(), KERN_INVALID_ADDRESS);
    
    return true;
}

bool test_memory_region_advanced_categorization()
{
    // Test various memory region types
    vm_region_submap_info_data_64_t info{};
    
    // Test malloc heap
    info = {};
    info.user_tag = VM_MEMORY_MALLOC;
    auto category = categorizeRegion(info, 0);
    EXPECT_EQ(category, std::string("Heap"));
    
    // Test malloc small heap
    info = {};
    info.user_tag = VM_MEMORY_MALLOC_SMALL;
    category = categorizeRegion(info, 0);
    EXPECT_EQ(category, std::string("Heap"));
    
    // Test malloc large heap
    info = {};
    info.user_tag = VM_MEMORY_MALLOC_LARGE;
    category = categorizeRegion(info, 0);
    EXPECT_EQ(category, std::string("Heap"));
    
    // Test dylib region
    info = {};
    info.user_tag = VM_MEMORY_DYLIB;
    category = categorizeRegion(info, 0);
    EXPECT_EQ(category, std::string("SharedLib"));
    
    // Test guard region (maps to Data since it's not specifically handled)
    info = {};
    info.user_tag = VM_MEMORY_GUARD;
    category = categorizeRegion(info, 0);
    EXPECT_EQ(category, std::string("Data"));
    
    return true;
}

bool test_value_monitor_concurrent_access()
{
    ValueMonitor monitor;
    
    // Add some addresses
    monitor.addAddress(0x1000, 4);
    monitor.addAddress(0x2000, 8);
    
    // Test concurrent access (basic thread safety check)
    std::vector<std::thread> threads;
    bool all_succeeded = true;
    
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([&monitor, &all_succeeded, i]() {
            try {
                monitor.addAddress(0x3000 + i * 0x1000, 4);
                auto tracked = monitor.tracked();
                if (tracked.size() < 2) { // Should have at least the original 2
                    all_succeeded = false;
                }
                monitor.removeAddress(0x3000 + i * 0x1000);
            } catch (...) {
                all_succeeded = false;
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_TRUE(all_succeeded);
    
    // Verify original addresses are still there
    auto final_tracked = monitor.tracked();
    EXPECT_EQ(final_tracked.size(), 2);
    
    return true;
}

struct TestCase {
    const char* name;
    bool (*function)();
};

const TestCase kTests[] = {
    // Value type and search algorithm tests
    {"SearchValue integer conversions", &test_search_value_integer},
    {"SearchValue floating conversions", &test_search_value_float},
    {"SearchValue edge cases", &test_search_value_edge_cases},
    {"SearchValue special floats", &test_search_value_special_floats},
    
    // Memory region parsing and categorization tests
    {"Protection flags conversion", &test_protection_flags},
    {"Memory region categorization", &test_region_categorization},
    {"Memory region advanced categorization", &test_memory_region_advanced_categorization},
    
    // Memory scanner tests
    {"MemoryScanner search results", &test_memory_scanner_search_results},
    {"MemoryScanner chunk reading", &test_memory_scanner_chunk_reading},
    
    // Process manager tests
    {"ProcessManager error handling", &test_process_manager_error_handling},
    {"ProcessManager state management", &test_process_manager_state_management},
    {"ProcessManager ownership validation", &test_process_manager_ownership_validation},
    
    // Security manager tests
    {"SecurityManager system process detection", &test_security_manager_system_process_detection},
    {"SecurityManager access evaluation", &test_security_manager_access_evaluation},
    
    // Error handling tests
    {"CheatEngineException handling", &test_cheat_engine_exception_handling},
    
    // Value monitor tests
    {"ValueMonitor address management", &test_value_monitor_address_management},
    {"ValueMonitor invalid task handling", &test_value_monitor_invalid_task},
    {"ValueMonitor concurrent access", &test_value_monitor_concurrent_access},
    
    // Memory writer tests
    {"MemoryWriter invalid parameters", &test_memory_writer_invalid_parameters},
    {"MemoryWriter history tracking", &test_memory_writer_history_tracking},
};

} // namespace

int main()
{
    int passed = 0;
    int failed = 0;

    for (const auto& test : kTests) {
        try {
            if (test.function()) {
                ++passed;
                std::cout << "[PASS] " << test.name << '\n';
            } else {
                ++failed;
                std::cout << "[FAIL] " << test.name << '\n';
            }
        } catch (const std::exception& ex) {
            ++failed;
            std::cout << "[FAIL] " << test.name << " (exception: " << ex.what() << ")\n";
        } catch (...) {
            ++failed;
            std::cout << "[FAIL] " << test.name << " (unknown exception)\n";
        }
    }

    std::cout << "Summary: " << passed << " passed, " << failed << " failed.\n";
    return failed == 0 ? 0 : 1;
}
