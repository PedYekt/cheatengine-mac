/**
 * @file application.hpp
 * @brief Core application types and configuration.
 */

#pragma once

#include "cheatengine/memory/memory_scanner.hpp"
#include "cheatengine/monitor/value_monitor.hpp"
#include "cheatengine/process/process_manager.hpp"
#include "cheatengine/process/security_manager.hpp"
#include "cheatengine/writer/memory_writer.hpp"

#include <chrono>
#include <string>

namespace cheatengine {

/**
 * @brief Configuration settings for the application.
 */
struct ApplicationConfig {
    // Search settings.
    /** Maximum number of search results. */
    size_t max_search_results = 1000;
    /** Size of each search chunk in bytes. */
    size_t search_chunk_size = 4096;

    // Monitoring settings.
    /** Interval between monitor polls in milliseconds. */
    std::chrono::milliseconds monitor_interval{100};
    /** Maximum number of monitored addresses. */
    size_t max_monitored_addresses = 100;

    // Display settings.
    /** Enable verbose error messages. */
    bool verbose_errors = true;
    /** Number of context bytes shown for results. */
    size_t context_bytes = 16;

    // Security settings.
    /** Allow memory writing operations. */
    bool enable_memory_writing = false;
    /** Require confirmation before writes. */
    bool require_confirmation_for_writes = true;

    // Performance settings.
    /** Timeout for memory reads in milliseconds. */
    size_t memory_read_timeout_ms = 5000;
    /** Enable page-aligned reading optimization. */
    bool use_chunked_reading = true;
};

/**
 * @brief Application coordinator for CheatEngine components.
 */
class Application {
public:
    /**
     * @brief Constructs the application.
     */
    Application();

    /**
     * @brief Destroys the application and releases resources.
     */
    ~Application();

    // Component access.

    /**
     * @brief Returns a mutable reference to the process manager.
     * @return Reference to the process manager.
     */
    ProcessManager& processManager() { return process_manager_; }

    /**
     * @brief Returns a mutable reference to the memory scanner.
     * @return Reference to the memory scanner.
     */
    MemoryScanner& memoryScanner() { return memory_scanner_; }

    /**
     * @brief Returns a mutable reference to the value monitor.
     * @return Reference to the value monitor.
     */
    ValueMonitor& valueMonitor() { return value_monitor_; }

    /**
     * @brief Returns a mutable reference to the memory writer.
     * @return Reference to the memory writer.
     */
    MemoryWriter& memoryWriter() { return memory_writer_; }

    /**
     * @brief Returns a mutable reference to the security manager.
     * @return Reference to the security manager.
     */
    SecurityManager& securityManager() { return security_manager_; }

    /**
     * @brief Returns a const reference to the process manager.
     * @return Const reference to the process manager.
     */
    const ProcessManager& processManager() const { return process_manager_; }

    /**
     * @brief Returns a const reference to the memory scanner.
     * @return Const reference to the memory scanner.
     */
    const MemoryScanner& memoryScanner() const { return memory_scanner_; }

    /**
     * @brief Returns a const reference to the value monitor.
     * @return Const reference to the value monitor.
     */
    const ValueMonitor& valueMonitor() const { return value_monitor_; }

    /**
     * @brief Returns a const reference to the memory writer.
     * @return Const reference to the memory writer.
     */
    const MemoryWriter& memoryWriter() const { return memory_writer_; }

    /**
     * @brief Returns a const reference to the security manager.
     * @return Const reference to the security manager.
     */
    const SecurityManager& securityManager() const { return security_manager_; }

    // Configuration management.

    /**
     * @brief Returns a mutable reference to the application configuration.
     * @return Reference to the configuration structure.
     */
    ApplicationConfig& config() { return config_; }

    /**
     * @brief Returns a const reference to the application configuration.
     * @return Const reference to the configuration structure.
     */
    const ApplicationConfig& config() const { return config_; }

    /**
     * @brief Loads configuration from a file.
     * @param config_file Path to configuration file, empty for default.
     */
    void loadConfig(const std::string& config_file = "");

    /**
     * @brief Saves the current configuration to a file.
     * @param config_file Path to configuration file, empty for default.
     */
    void saveConfig(const std::string& config_file = "");

    // Application lifecycle.

    /**
     * @brief Initializes the application.
     * @return true if initialization succeeds, false otherwise.
     */
    bool initialize();

    /**
     * @brief Shuts down the application and releases resources.
     */
    void shutdown();

    /**
     * @brief Returns whether the application is initialized.
     * @return true if initialized, false otherwise.
     */
    bool isInitialized() const { return initialized_; }

    // Error handling and reporting.

    /**
     * @brief Returns the last error message.
     * @return Last error message or empty string.
     */
    std::string getLastError() const { return last_error_; }

    /**
     * @brief Clears the current error state.
     */
    void clearError() { last_error_.clear(); }

    // Integrated operations that coordinate multiple components.

    /**
     * @brief Attaches to a process with validation.
     * @param pid Process ID to attach to.
     * @return true if the attachment succeeds, false otherwise.
     */
    bool attachToProcessWithValidation(pid_t pid);

    /**
     * @brief Detaches from the current process and cleans up resources.
     */
    void detachWithCleanup();

    /**
     * @brief Writes memory with security validation.
     * @param address Target memory address.
     * @param data Data to write.
     * @return true if the write succeeds, false otherwise.
     */
    bool performSecureMemoryWrite(mach_vm_address_t address, const std::vector<uint8_t>& data);

private:
    /**
     * @brief Sets the current error message.
     * @param error Error message to store.
     */
    void setError(const std::string& error) { last_error_ = error; }

    // Core components.
    /** Handles process attachment and management. */
    ProcessManager process_manager_;
    /** Performs memory enumeration and searching. */
    MemoryScanner memory_scanner_;
    /** Tracks memory changes over time. */
    ValueMonitor value_monitor_;
    /** Handles safe memory modification. */
    MemoryWriter memory_writer_;
    /** Manages security validation and compliance. */
    SecurityManager security_manager_;

    // Application state.
    /** Current application configuration. */
    ApplicationConfig config_;
    /** Initialization state flag. */
    bool initialized_ = false;
    /** Last error message for user feedback. */
    std::string last_error_;
};

} // namespace cheatengine
