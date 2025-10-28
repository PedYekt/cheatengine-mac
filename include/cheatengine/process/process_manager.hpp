/**
 * @file process_manager.hpp
 * @brief Process attachment and management using Mach APIs
 * 
 * This file demonstrates how to safely attach to and manage processes on macOS
 * using Mach kernel APIs while respecting security boundaries and system policies.
 * 
 * Educational Focus:
 * - Mach task port acquisition and management
 * - macOS security model integration (SIP, entitlements, code signing)
 * - Process ownership validation and security boundaries
 * - Resource lifecycle management for system handles
 * - Error handling for security-sensitive operations
 */

#pragma once

#include <mach/mach.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>

namespace cheatengine {

class SecurityManager;

/**
 * @brief Process attachment and management component
 * 
 * The ProcessManager class demonstrates how to safely interact with processes
 * on macOS while respecting security boundaries. It showcases the integration
 * of Mach APIs with modern security features like SIP and code signing.
 * 
 * Educational Concepts Demonstrated:
 * - Mach task port acquisition using task_for_pid
 * - Process ownership validation for security
 * - macOS security model integration (SIP, entitlements)
 * - Resource lifecycle management (RAII for system handles)
 * - Security-aware error handling and user guidance
 * 
 * Security Features:
 * - Process ownership validation before attachment
 * - Integration with macOS security policies
 * - Comprehensive error reporting with security context
 * - Graceful handling of permission denials
 * 
 * Mach APIs Used:
 * - task_for_pid: Acquire task port for process access
 * - mach_port_deallocate: Clean up task ports
 * - Process validation using proc APIs
 * 
 * @note This class follows RAII principles for automatic resource cleanup
 *       and is designed to be move-only to prevent accidental resource duplication.
 */
class ProcessManager {
public:
    /**
     * @brief Construct a new ProcessManager
     * 
     * Initializes the process manager without attaching to any process.
     * Demonstrates two-phase initialization for system resources.
     */
    ProcessManager();
    
    /**
     * @brief Destroy the ProcessManager and clean up resources
     * 
     * Automatically detaches from any attached process and releases
     * system resources. Demonstrates RAII resource management.
     */
    ~ProcessManager();
    
    // Non-copyable but movable - demonstrate resource management patterns
    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;
    ProcessManager(ProcessManager&&) = default;
    ProcessManager& operator=(ProcessManager&&) = default;
    
    /**
     * @brief Possible outcomes of process attachment attempts
     * 
     * These error codes provide educational insight into the various ways
     * process attachment can fail on macOS, each representing different
     * aspects of the system's security model.
     */
    enum class AttachmentError {
        SUCCESS,                ///< Attachment succeeded with full access
        INVALID_PID,           ///< Process ID is invalid or malformed
        PERMISSION_DENIED,     ///< General permission denial from system
        MISSING_ENTITLEMENTS,  ///< Required entitlements not present in code signature
        SIP_PROTECTED,         ///< System Integrity Protection blocks access
        PROCESS_NOT_FOUND,     ///< Process ID does not exist or has terminated
        TASK_PORT_FAILED       ///< task_for_pid system call failed
    };
    
    /**
     * @brief Current state of process attachment
     * 
     * Tracks the lifecycle of process attachment operations, useful for
     * understanding the asynchronous nature of system operations.
     */
    enum class ProcessState {
        DETACHED,      ///< No process attached, ready for new attachment
        ATTACHING,     ///< Attachment in progress (for async operations)
        ATTACHED,      ///< Successfully attached with active task port
        DETACHING,     ///< Detachment in progress (cleanup phase)
        ERROR_STATE    ///< Attachment failed, error information available
    };
    
    /**
     * @brief Comprehensive information about an attached process
     * 
     * This structure demonstrates how to capture and manage all relevant
     * information about a process attachment, including security context
     * and access level information.
     */
    struct ProcessInfo {
        pid_t pid{0};                                           ///< Process identifier
        std::string executable_path;                            ///< Full path to executable
        task_t task_port{MACH_PORT_NULL};                      ///< Mach task port for memory access
        bool is_attached{false};                               ///< Whether attachment is active
        bool has_full_access{false};                           ///< true if task port available, false if limited to proc APIs
        ProcessState state{ProcessState::DETACHED};            ///< Current attachment state
        std::chrono::steady_clock::time_point attach_time;     ///< When attachment occurred
    };
    
    /**
     * @brief Security context information for the current application
     * 
     * Provides educational insight into the macOS security model by showing
     * which security features are active and how they affect process access.
     */
    struct SecurityContext {
        bool has_get_task_allow{false};     ///< Whether get-task-allow entitlement is present
        bool is_code_signed{false};         ///< Whether application is properly code signed
        bool sip_enabled{false};            ///< Whether System Integrity Protection is active
        std::string entitlements_status;    ///< Detailed entitlements information
    };

    /**
     * @brief Attach to a process with comprehensive security validation
     * @param pid Process ID to attach to
     * @return true if attachment succeeded with full access
     * 
     * This method demonstrates the complete process attachment workflow on macOS,
     * including security validation, ownership checking, and task port acquisition.
     * 
     * Educational Concepts:
     * - Process ownership validation for security
     * - task_for_pid API usage and error handling
     * - macOS security model integration
     * - Resource acquisition and cleanup patterns
     * 
     * Security Features:
     * - Validates process ownership before attachment
     * - Checks for required entitlements and code signing
     * - Respects System Integrity Protection boundaries
     * - Provides detailed error information for learning
     * 
     * @throws ProcessAttachmentError with detailed context on failure
     */
    bool attachToProcess(pid_t pid);
    
    /**
     * @brief Detach from the current process and clean up resources
     * 
     * Demonstrates proper cleanup of system resources including task ports
     * and any cached process information. Shows RAII principles in action.
     * 
     * Educational Note: This method ensures complete cleanup even if the
     * process has terminated or become inaccessible since attachment.
     */
    void detachFromProcess();
    
    /**
     * @brief Get information about the currently attached process
     * @return ProcessInfo Complete information about attached process
     * 
     * Provides comprehensive process information including security context,
     * access level, and attachment metadata for educational analysis.
     */
    [[nodiscard]] ProcessInfo getCurrentProcess() const;
    
    /**
     * @brief Validate that a process is owned by the current user
     * @param pid Process ID to validate
     * @return true if process is owned by current user
     * 
     * Demonstrates security boundary validation using process ownership.
     * This is a fundamental security check that prevents unauthorized
     * access to other users' processes.
     * 
     * Educational Value: Shows how to implement security boundaries
     * and validate permissions before performing privileged operations.
     */
    [[nodiscard]] bool validateProcessOwnership(pid_t pid) const;
    
    /**
     * @brief Get the last attachment error that occurred
     * @return AttachmentError The most recent error code
     */
    [[nodiscard]] AttachmentError getLastError() const { return last_error_; }
    
    /**
     * @brief Get current security context information
     * @return SecurityContext Information about security features and status
     * 
     * Provides educational insight into the current security environment,
     * including entitlements, code signing status, and SIP configuration.
     */
    [[nodiscard]] SecurityContext getSecurityContext() const;
    
    /**
     * @brief Get human-readable description of an attachment error
     * @param error AttachmentError to describe
     * @return std::string Educational description of the error
     * 
     * Provides educational error descriptions that help users understand
     * the underlying system concepts and security mechanisms.
     */
    [[nodiscard]] std::string getErrorDescription(AttachmentError error) const;
    
    /**
     * @brief Get security guidance for resolving access issues
     * @return std::string Detailed guidance for security configuration
     * 
     * Provides actionable guidance for resolving security-related issues,
     * including code signing, entitlements, and SIP considerations.
     */
    [[nodiscard]] std::string getSecurityGuidance() const;
    
    /**
     * @brief Get the current process attachment state
     * @return ProcessState Current state of the process manager
     */
    [[nodiscard]] ProcessState getCurrentState() const { return current_process_.state; }
    
    /**
     * @brief Check if a process is still running
     * @param pid Process ID to check
     * @return true if process exists and is accessible
     * 
     * Demonstrates process lifecycle monitoring and shows how to detect
     * when attached processes terminate or become inaccessible.
     */
    [[nodiscard]] bool isProcessAlive(pid_t pid) const;
    
    /**
     * @brief Validate that the current process attachment is still valid
     * @return true if attachment is valid and process is accessible
     * 
     * Performs comprehensive validation of the current attachment including
     * process existence, task port validity, and access permissions.
     */
    [[nodiscard]] bool validateCurrentProcess() const;

    // Legacy methods for backward compatibility
    bool attach(pid_t pid) { return attachToProcess(pid); }
    void detach() { detachFromProcess(); }
    [[nodiscard]] std::optional<ProcessInfo> currentProcess() const noexcept;
    [[nodiscard]] bool ownsProcess(pid_t pid) const { return validateProcessOwnership(pid); }
    [[nodiscard]] const std::string& lastError() const noexcept { return last_error_string_; }
    [[nodiscard]] int lastMachError() const noexcept { return last_mach_error_; }

private:
    bool acquireTaskPort(pid_t pid, task_t& task_port);
    bool checkEntitlements() const;
    bool isSystemProcess(pid_t pid) const;
    bool isSIPProtected(pid_t pid) const;
    void resetState();

    ProcessInfo current_process_;
    AttachmentError last_error_{AttachmentError::SUCCESS};
    std::string last_error_string_;
    int last_mach_error_{0};
    std::unique_ptr<SecurityManager> security_manager_;
};

} // namespace cheatengine
