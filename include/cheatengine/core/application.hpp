/**
 * @file application.hpp
 * @brief Core CheatEngine application class and configuration
 * 
 * This file contains the main Application class that coordinates all CheatEngine components
 * and demonstrates how to build a memory analysis tool using macOS Mach APIs.
 * 
 * Educational Focus:
 * - Component coordination and lifecycle management
 * - Configuration management patterns
 * - Error handling strategies in system programming
 * - Integration of multiple system APIs (Mach VM, process management, security)
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
 * @brief Configuration structure for CheatEngine application
 * 
 * This structure demonstrates how to organize application settings and provides
 * educational examples of performance tuning parameters for memory operations.
 * 
 * Educational Concepts:
 * - Memory access optimization through chunking
 * - Rate limiting for system resource protection
 * - Security-conscious default settings
 * - Performance vs. safety trade-offs
 */
struct ApplicationConfig {
    // Search settings - demonstrate memory scanning optimization
    size_t max_search_results = 1000;      ///< Limit results to prevent memory exhaustion
    size_t search_chunk_size = 4096;       ///< Page-aligned chunks for optimal VM performance
    
    // Monitoring settings - demonstrate real-time system programming
    std::chrono::milliseconds monitor_interval{100};  ///< Balance responsiveness vs CPU usage
    size_t max_monitored_addresses = 100;             ///< Prevent excessive system call overhead
    
    // Display settings - educational and user experience features
    bool show_educational_info = true;      ///< Display learning-focused explanations
    bool verbose_errors = true;             ///< Detailed error messages for learning
    size_t context_bytes = 16;              ///< Memory context around search results
    
    // Security settings - demonstrate secure-by-default principles
    bool enable_memory_writing = false;                ///< Disabled by default for safety
    bool require_confirmation_for_writes = true;      ///< Explicit consent for modifications
    
    // Performance settings - demonstrate system programming optimization
    size_t memory_read_timeout_ms = 5000;   ///< Prevent hanging on slow memory operations
    bool use_chunked_reading = true;        ///< Enable page-aligned reading optimization
};

/**
 * @brief Main CheatEngine application class
 * 
 * The Application class serves as the central coordinator for all CheatEngine components,
 * demonstrating how to build a complex system programming application that integrates
 * multiple macOS APIs while maintaining security and educational value.
 * 
 * Educational Concepts Demonstrated:
 * - Component-based architecture design
 * - Resource lifecycle management (RAII principles)
 * - Error propagation and handling strategies
 * - Configuration management patterns
 * - Integration of system APIs (Mach VM, process management, security)
 * - Secure-by-default design principles
 * 
 * Architecture Pattern:
 * This class follows the Facade pattern, providing a simplified interface to the
 * complex subsystem of memory analysis components. It demonstrates how to coordinate
 * multiple system-level components while maintaining clean separation of concerns.
 * 
 * @note This class is designed for educational purposes and should only be used
 *       on processes owned by the current user.
 */
class Application {
public:
    /**
     * @brief Construct a new Application instance
     * 
     * Initializes all component instances but does not perform any system calls.
     * Actual initialization happens in initialize() to allow for proper error handling.
     * 
     * Educational Note: This demonstrates the two-phase initialization pattern
     * commonly used in system programming to separate object construction from
     * resource acquisition.
     */
    Application();
    
    /**
     * @brief Destroy the Application instance
     * 
     * Ensures proper cleanup of all resources and components. Automatically calls
     * shutdown() if the application is still initialized.
     * 
     * Educational Note: Demonstrates RAII (Resource Acquisition Is Initialization)
     * principles for automatic resource management.
     */
    ~Application();
    
    // Component access - demonstrate component-based architecture
    
    /**
     * @brief Get mutable reference to the process manager
     * @return ProcessManager& Reference to the process management component
     * 
     * The ProcessManager handles process attachment, validation, and task port management.
     * It demonstrates how to safely interact with macOS process security mechanisms.
     */
    ProcessManager& processManager() { return process_manager_; }
    
    /**
     * @brief Get mutable reference to the memory scanner
     * @return MemoryScanner& Reference to the memory scanning component
     * 
     * The MemoryScanner demonstrates efficient memory enumeration and searching
     * using Mach VM APIs, showcasing virtual memory management concepts.
     */
    MemoryScanner& memoryScanner() { return memory_scanner_; }
    
    /**
     * @brief Get mutable reference to the value monitor
     * @return ValueMonitor& Reference to the value monitoring component
     * 
     * The ValueMonitor demonstrates real-time memory monitoring and change detection,
     * illustrating concepts of temporal locality and memory access patterns.
     */
    ValueMonitor& valueMonitor() { return value_monitor_; }
    
    /**
     * @brief Get mutable reference to the memory writer
     * @return MemoryWriter& Reference to the memory writing component
     * 
     * The MemoryWriter demonstrates safe memory modification techniques and
     * permission validation, showing how to respect memory protection boundaries.
     */
    MemoryWriter& memoryWriter() { return memory_writer_; }
    
    /**
     * @brief Get mutable reference to the security manager
     * @return SecurityManager& Reference to the security management component
     * 
     * The SecurityManager demonstrates macOS security model integration,
     * including SIP, code signing, and entitlement validation.
     */
    SecurityManager& securityManager() { return security_manager_; }

    // Const versions for read-only access
    const ProcessManager& processManager() const { return process_manager_; }
    const MemoryScanner& memoryScanner() const { return memory_scanner_; }
    const ValueMonitor& valueMonitor() const { return value_monitor_; }
    const MemoryWriter& memoryWriter() const { return memory_writer_; }
    const SecurityManager& securityManager() const { return security_manager_; }
    
    // Configuration management - demonstrate configuration patterns
    
    /**
     * @brief Get mutable reference to application configuration
     * @return ApplicationConfig& Reference to the configuration structure
     * 
     * Allows runtime modification of application behavior, demonstrating
     * how to build configurable system applications.
     */
    ApplicationConfig& config() { return config_; }
    
    /**
     * @brief Get read-only reference to application configuration
     * @return const ApplicationConfig& Const reference to the configuration
     */
    const ApplicationConfig& config() const { return config_; }
    
    /**
     * @brief Load configuration from file
     * @param config_file Path to configuration file (empty for default location)
     * 
     * Demonstrates configuration persistence and file I/O patterns.
     * Educational Note: Shows how to handle optional parameters and default values.
     */
    void loadConfig(const std::string& config_file = "");
    
    /**
     * @brief Save current configuration to file
     * @param config_file Path to configuration file (empty for default location)
     * 
     * Demonstrates configuration serialization and error handling for file operations.
     */
    void saveConfig(const std::string& config_file = "");
    
    // Application lifecycle - demonstrate resource management patterns
    
    /**
     * @brief Initialize the application and all components
     * @return true if initialization succeeded, false otherwise
     * 
     * Performs system-level initialization including security validation,
     * component setup, and resource allocation. This demonstrates the
     * two-phase initialization pattern for robust error handling.
     * 
     * Educational Concepts:
     * - Two-phase initialization for system resources
     * - Early validation of system requirements
     * - Graceful handling of initialization failures
     */
    bool initialize();
    
    /**
     * @brief Shutdown the application and release all resources
     * 
     * Performs orderly shutdown of all components and releases system resources.
     * Demonstrates proper cleanup patterns for system programming.
     * 
     * Educational Note: Shows how to handle cleanup in the presence of errors
     * and ensure no resources are leaked.
     */
    void shutdown();
    
    /**
     * @brief Check if the application is properly initialized
     * @return true if initialized and ready for use
     * 
     * Provides a way to verify application state before performing operations.
     * Demonstrates defensive programming practices.
     */
    bool isInitialized() const { return initialized_; }
    
    // Error handling and reporting - demonstrate error management patterns
    
    /**
     * @brief Get the last error message
     * @return std::string Description of the last error that occurred
     * 
     * Provides human-readable error information for debugging and user feedback.
     * Demonstrates error message management in system applications.
     */
    std::string getLastError() const { return last_error_; }
    
    /**
     * @brief Clear the current error state
     * 
     * Resets error state for fresh operations. Demonstrates error state management.
     */
    void clearError() { last_error_.clear(); }
    
    // Integrated operations that coordinate multiple components
    
    /**
     * @brief Attach to a process with comprehensive validation
     * @param pid Process ID to attach to
     * @return true if attachment succeeded with full validation
     * 
     * This method demonstrates how to coordinate multiple components for a complex
     * operation. It combines process management, security validation, and error
     * handling into a single, safe operation.
     * 
     * Educational Concepts:
     * - Multi-component coordination
     * - Comprehensive error handling
     * - Security-first design
     * - Transaction-like operations (all-or-nothing)
     * 
     * Security Features:
     * - Process ownership validation
     * - Security context evaluation
     * - Entitlement verification
     * - SIP compliance checking
     */
    bool attachToProcessWithValidation(pid_t pid);
    
    /**
     * @brief Detach from current process with complete cleanup
     * 
     * Performs comprehensive cleanup including monitored addresses, cached data,
     * and system resources. Demonstrates proper resource cleanup patterns.
     * 
     * Educational Note: Shows how to ensure complete cleanup even when
     * individual components might fail during shutdown.
     */
    void detachWithCleanup();
    
    /**
     * @brief Perform a memory write operation with security validation
     * @param address Target memory address
     * @param data Data to write
     * @return true if write succeeded with all security checks
     * 
     * This method demonstrates secure memory modification with comprehensive
     * validation and logging. It shows how to build safe interfaces for
     * potentially dangerous operations.
     * 
     * Educational Concepts:
     * - Permission validation before dangerous operations
     * - Audit logging for security-sensitive actions
     * - Multi-layer security validation
     * - Safe handling of memory modification
     * 
     * Security Features:
     * - Memory region permission validation
     * - User confirmation requirements
     * - Operation logging and audit trail
     * - Rollback capability on failure
     */
    bool performSecureMemoryWrite(mach_vm_address_t address, const std::vector<uint8_t>& data);
    
private:
    /**
     * @brief Set the current error message
     * @param error Error description to store
     * 
     * Internal method for consistent error reporting across the application.
     */
    void setError(const std::string& error) { last_error_ = error; }

    
private:
    // Core components - demonstrate component-based architecture
    ProcessManager process_manager_;        ///< Handles process attachment and management
    MemoryScanner memory_scanner_;         ///< Performs memory enumeration and searching
    ValueMonitor value_monitor_;           ///< Tracks memory changes over time
    MemoryWriter memory_writer_;           ///< Handles safe memory modification
    SecurityManager security_manager_;     ///< Manages security validation and compliance
    
    // Application state - demonstrate state management patterns
    ApplicationConfig config_;             ///< Current application configuration
    bool initialized_ = false;             ///< Initialization state flag
    std::string last_error_;              ///< Last error message for user feedback
};

} // namespace cheatengine
