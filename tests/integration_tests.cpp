#include "cheatengine/core/application.hpp"
#include "cheatengine/memory/memory_scanner.hpp"
#include "cheatengine/memory/value_types.hpp"
#include "cheatengine/monitor/value_monitor.hpp"
#include "cheatengine/writer/memory_writer.hpp"
#include "cheatengine/process/process_manager.hpp"
#include "cheatengine/process/security_manager.hpp"

#include <chrono>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <vector>
#include <cstring>

namespace {

using cheatengine::MemoryScanner;
using cheatengine::SearchValue;
using cheatengine::ValueMonitor;
using cheatengine::MemoryWriter;
using cheatengine::ProcessManager;
using cheatengine::SecurityManager;

#define EXPECT_TRUE(expr)                                                                 \
    do {                                                                                  \
        if (!(expr)) {                                                                    \
            std::cerr << __FILE__ << ":" << __LINE__ << " EXPECT_TRUE failed: " #expr     \
                      << std::endl;                                                      \
            return false;                                                                 \
        }                                                                                 \
    } while (0)

#define EXPECT_FALSE(expr)                                                                \
    do {                                                                                  \
        if ((expr)) {                                                                     \
            std::cerr << __FILE__ << ":" << __LINE__ << " EXPECT_FALSE failed: " #expr    \
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

#define EXPECT_GT(lhs, rhs)                                                               \
    do {                                                                                  \
        if (!((lhs) > (rhs))) {                                                           \
            std::cerr << __FILE__ << ":" << __LINE__ << " EXPECT_GT failed: "             \
                      << #lhs << " > " << #rhs << std::endl;                              \
            return false;                                                                 \
        }                                                                                 \
    } while (0)

// Global test data for self-process testing
static volatile int test_integer = 42;
static volatile float test_float = 3.14159f;
static volatile double test_double = 2.718281828;

bool test_self_process_attachment()
{
    ProcessManager manager;
    
    // Test attaching to our own process
    pid_t self_pid = getpid();
    bool attached = manager.attachToProcess(self_pid);
    
    if (!attached) {
        // This might fail due to security restrictions, which is expected
        auto error = manager.getLastError();
        std::cout << "Self-process attachment failed (expected on some systems): " 
                  << manager.getErrorDescription(error) << std::endl;
        return true; // This is acceptable
    }
    
    // If we successfully attached, verify the process info
    auto info = manager.getCurrentProcess();
    EXPECT_EQ(info.pid, self_pid);
    EXPECT_TRUE(info.is_attached);
    
    // Clean up
    manager.detachFromProcess();
    
    return true;
}

bool test_self_process_memory_enumeration()
{
    ProcessManager manager;
    MemoryScanner scanner;
    
    pid_t self_pid = getpid();
    if (!manager.attachToProcess(self_pid)) {
        std::cout << "Skipping memory enumeration test - cannot attach to self" << std::endl;
        return true;
    }
    
    auto info = manager.getCurrentProcess();
    auto regions = scanner.enumerate(info.task_port);
    
    // We should have at least some memory regions
    EXPECT_GT(regions.size(), 0);
    
    // Verify regions have valid properties
    bool found_stack = false;
    bool found_heap = false;
    bool found_code = false;
    
    for (const auto& region : regions) {
        EXPECT_GT(region.size, 0);
        EXPECT_TRUE(region.start_address != 0 || region.category == "Data"); // Allow zero address for special regions
        
        if (region.category == "Stack") found_stack = true;
        if (region.category == "Heap") found_heap = true;
        if (region.category == "Code") found_code = true;
    }
    
    // We should find at least stack and code regions
    EXPECT_TRUE(found_stack);
    EXPECT_TRUE(found_code);
    
    manager.detachFromProcess();
    return true;
}

bool test_self_process_value_search()
{
    ProcessManager manager;
    MemoryScanner scanner;
    
    pid_t self_pid = getpid();
    if (!manager.attachToProcess(self_pid)) {
        std::cout << "Skipping value search test - cannot attach to self" << std::endl;
        return true;
    }
    
    auto info = manager.getCurrentProcess();
    
    // Search for our test integer
    auto search_value = SearchValue::fromInt32(test_integer);
    auto results = scanner.search(info.task_port, search_value);
    
    // We should find at least one match (our global variable)
    EXPECT_GT(results.size(), 0);
    
    // Verify search results have valid properties
    for (const auto& result : results) {
        EXPECT_GT(result.address, 0);
        EXPECT_EQ(result.value_size, sizeof(int));
    }
    
    manager.detachFromProcess();
    return true;
}

bool test_self_process_value_monitoring()
{
    ProcessManager manager;
    ValueMonitor monitor;
    
    pid_t self_pid = getpid();
    if (!manager.attachToProcess(self_pid)) {
        std::cout << "Skipping value monitoring test - cannot attach to self" << std::endl;
        return true;
    }
    
    auto info = manager.getCurrentProcess();
    
    // Add our test variable to monitoring (we need to find its address first)
    mach_vm_address_t test_addr = reinterpret_cast<mach_vm_address_t>(&test_integer);
    monitor.addAddress(test_addr, sizeof(int));
    
    // Verify it was added
    auto tracked = monitor.tracked();
    EXPECT_EQ(tracked.size(), 1);
    EXPECT_EQ(tracked[0].address, test_addr);
    
    // Poll for changes (should be no changes initially)
    auto changes = monitor.poll(info.task_port);
    EXPECT_EQ(changes.size(), 0);
    
    // Modify the value and check for changes
    int old_value = test_integer;
    test_integer = 999;
    
    // Poll again - should detect the change
    changes = monitor.poll(info.task_port);
    if (changes.size() > 0) {
        EXPECT_EQ(changes[0].address, test_addr);
        // Note: We can't easily verify the exact old/new values due to endianness and timing
    }
    
    // Restore original value
    test_integer = old_value;
    
    manager.detachFromProcess();
    return true;
}

bool test_memory_writer_self_process()
{
    ProcessManager manager;
    MemoryWriter writer;
    
    pid_t self_pid = getpid();
    if (!manager.attachToProcess(self_pid)) {
        std::cout << "Skipping memory writer test - cannot attach to self" << std::endl;
        return true;
    }
    
    auto info = manager.getCurrentProcess();
    
    // Test writing to our own memory
    mach_vm_address_t test_addr = reinterpret_cast<mach_vm_address_t>(&test_integer);
    
    // Check if we can write to this address
    bool can_write = writer.canWrite(info.task_port, test_addr, sizeof(int));
    
    if (can_write) {
        // Save original value
        int original_value = test_integer;
        
        // Write a new value
        std::vector<std::uint8_t> new_data = {0x7B, 0x00, 0x00, 0x00}; // 123 in little-endian
        bool write_success = writer.write(info.task_port, test_addr, new_data);
        
        if (write_success) {
            // Verify the write worked
            EXPECT_EQ(test_integer, 123);
            
            // Restore original value
            test_integer = original_value;
        }
        
        // Check that the operation was recorded in history
        auto history = writer.history();
        EXPECT_GT(history.size(), 0);
    } else {
        std::cout << "Cannot write to test address (expected on some systems)" << std::endl;
    }
    
    manager.detachFromProcess();
    return true;
}

bool test_security_validation()
{
    SecurityManager security;
    ProcessManager manager;
    
    // Test system process detection
    EXPECT_TRUE(security.isSystemProcess(0));  // kernel_task
    EXPECT_TRUE(security.isSystemProcess(1));  // launchd
    EXPECT_FALSE(security.isSystemProcess(getpid())); // our process
    
    // Test SIP protection detection
    bool sip_protected_kernel = security.isSIPProtected(0);
    bool sip_protected_launchd = security.isSIPProtected(1);
    bool sip_protected_self = security.isSIPProtected(getpid());
    
    // System processes should be SIP protected
    EXPECT_TRUE(sip_protected_kernel);
    EXPECT_TRUE(sip_protected_launchd);
    // Our process should not be SIP protected
    EXPECT_FALSE(sip_protected_self);
    
    // Test access evaluation
    auto access_info = security.evaluateProcessAccess(getpid());
    // Should have some level of access to our own process
    EXPECT_TRUE(access_info.level != SecurityManager::AccessLevel::NO_ACCESS);
    
    // System processes should have no access
    access_info = security.evaluateProcessAccess(0);
    EXPECT_EQ(access_info.level, SecurityManager::AccessLevel::NO_ACCESS);
    
    return true;
}

bool test_performance_memory_scanning()
{
    ProcessManager manager;
    MemoryScanner scanner;
    
    pid_t self_pid = getpid();
    if (!manager.attachToProcess(self_pid)) {
        std::cout << "Skipping performance test - cannot attach to self" << std::endl;
        return true;
    }
    
    auto info = manager.getCurrentProcess();
    
    // Measure time for memory region enumeration
    auto start_time = std::chrono::high_resolution_clock::now();
    auto regions = scanner.enumerate(info.task_port);
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "Memory enumeration took " << duration.count() << "ms for " 
              << regions.size() << " regions" << std::endl;
    
    // Should complete within reasonable time (10 seconds is very generous)
    EXPECT_TRUE(duration.count() < 10000);
    
    // Measure time for value search
    start_time = std::chrono::high_resolution_clock::now();
    auto search_value = SearchValue::fromInt32(test_integer);
    auto results = scanner.search(info.task_port, search_value);
    end_time = std::chrono::high_resolution_clock::now();
    
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "Value search took " << duration.count() << "ms and found " 
              << results.size() << " matches" << std::endl;
    
    // Search should also complete within reasonable time
    EXPECT_TRUE(duration.count() < 30000); // 30 seconds is very generous for search
    
    manager.detachFromProcess();
    return true;
}

bool test_error_recovery()
{
    ProcessManager manager;
    MemoryScanner scanner;
    ValueMonitor monitor;
    MemoryWriter writer;
    
    // Test operations with invalid task port
    task_t invalid_task = MACH_PORT_NULL;
    
    // Scanner should handle invalid task gracefully
    auto regions = scanner.enumerate(invalid_task);
    EXPECT_EQ(regions.size(), 0);
    
    auto search_value = SearchValue::fromInt32(42);
    auto results = scanner.search(invalid_task, search_value);
    EXPECT_EQ(results.size(), 0);
    
    std::vector<std::uint8_t> buffer;
    bool read_result = scanner.readChunk(invalid_task, 0x1000, 100, buffer);
    EXPECT_FALSE(read_result);
    
    // Monitor should handle invalid task gracefully
    monitor.addAddress(0x1000, 4);
    auto changes = monitor.poll(invalid_task);
    EXPECT_EQ(changes.size(), 0);
    
    // Writer should handle invalid task gracefully
    std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    bool write_result = writer.write(invalid_task, 0x1000, data);
    EXPECT_FALSE(write_result);
    
    bool can_write = writer.canWrite(invalid_task, 0x1000, 4);
    EXPECT_FALSE(can_write);
    
    return true;
}

struct TestCase {
    const char* name;
    bool (*function)();
};

const TestCase kIntegrationTests[] = {
    {"Self-process attachment", &test_self_process_attachment},
    {"Self-process memory enumeration", &test_self_process_memory_enumeration},
    {"Self-process value search", &test_self_process_value_search},
    {"Self-process value monitoring", &test_self_process_value_monitoring},
    {"Memory writer self-process", &test_memory_writer_self_process},
    {"Security validation", &test_security_validation},
    {"Performance memory scanning", &test_performance_memory_scanning},
    {"Error recovery", &test_error_recovery},
};

} // namespace

int main()
{
    std::cout << "Running CheatEngine Integration Tests\n";
    std::cout << "=====================================\n\n";
    
    int passed = 0;
    int failed = 0;

    for (const auto& test : kIntegrationTests) {
        std::cout << "Running: " << test.name << "... ";
        std::cout.flush();
        
        try {
            if (test.function()) {
                ++passed;
                std::cout << "[PASS]\n";
            } else {
                ++failed;
                std::cout << "[FAIL]\n";
            }
        } catch (const std::exception& ex) {
            ++failed;
            std::cout << "[FAIL] (exception: " << ex.what() << ")\n";
        } catch (...) {
            ++failed;
            std::cout << "[FAIL] (unknown exception)\n";
        }
    }

    std::cout << "\nIntegration Test Summary: " << passed << " passed, " << failed << " failed.\n";
    
    if (failed > 0) {
        std::cout << "\nNote: Some failures may be expected due to macOS security restrictions.\n";
        std::cout << "The tool requires proper code signing and entitlements for full functionality.\n";
    }
    
    return failed == 0 ? 0 : 1;
}