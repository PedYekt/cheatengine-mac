#pragma once

#include "cheatengine/memory/memory_scanner.hpp"
#include "cheatengine/monitor/value_monitor.hpp"
#include "cheatengine/process/process_manager.hpp"
#include "cheatengine/process/security_manager.hpp"
#include "cheatengine/writer/memory_writer.hpp"

#include <chrono>
#include <string>

namespace cheatengine {

struct ApplicationConfig {
    size_t max_search_results = 1000;
    size_t search_chunk_size = 4096;
    std::chrono::milliseconds monitor_interval{100};
    size_t max_monitored_addresses = 100;
    bool verbose_errors = true;
    size_t context_bytes = 16;
    bool enable_memory_writing = true;
    bool require_confirmation_for_writes = true;
    size_t memory_read_timeout_ms = 5000;
    bool use_chunked_reading = true;
};

class Application {
public:
    Application();
    ~Application();

    ProcessManager& processManager() { return process_manager_; }
    MemoryScanner& memoryScanner() { return memory_scanner_; }
    ValueMonitor& valueMonitor() { return value_monitor_; }
    MemoryWriter& memoryWriter() { return memory_writer_; }
    SecurityManager& securityManager() { return security_manager_; }

    const ProcessManager& processManager() const { return process_manager_; }
    const MemoryScanner& memoryScanner() const { return memory_scanner_; }
    const ValueMonitor& valueMonitor() const { return value_monitor_; }
    const MemoryWriter& memoryWriter() const { return memory_writer_; }
    const SecurityManager& securityManager() const { return security_manager_; }

    const ApplicationConfig& config() const { return config_; }

    bool initialize();
    void shutdown();
    bool isInitialized() const { return initialized_; }

    std::string getLastError() const { return last_error_; }
    void clearError() { last_error_.clear(); }

    bool attachToProcessWithValidation(pid_t pid);
    void detachWithCleanup();
    bool performSecureMemoryWrite(mach_vm_address_t address, const std::vector<uint8_t>& data);

private:
    void setError(const std::string& error) { last_error_ = error; }

    ProcessManager process_manager_;
    MemoryScanner memory_scanner_;
    ValueMonitor value_monitor_;
    MemoryWriter memory_writer_;
    SecurityManager security_manager_;

    ApplicationConfig config_;
    bool initialized_ = false;
    std::string last_error_;
};

} // namespace cheatengine
