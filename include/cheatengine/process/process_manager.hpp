/**
 * @file process_manager.hpp
 * @brief Process attachment and management using Mach APIs
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
 */
class ProcessManager {
public:
    /**
     * @brief Construct a new ProcessManager
     */
    ProcessManager();
    
    /**
     * @brief Destroy the ProcessManager and clean up resources
     */
    ~ProcessManager();
    
    /** @brief Deleted copy constructor. */
    ProcessManager(const ProcessManager&) = delete;
    /** @brief Deleted copy assignment operator. */
    ProcessManager& operator=(const ProcessManager&) = delete;
    /** @brief Defaulted move constructor. */
    ProcessManager(ProcessManager&&) = default;
    /** @brief Defaulted move assignment operator. */
    ProcessManager& operator=(ProcessManager&&) = default;
    
    /**
     * @brief Possible outcomes of process attachment attempts
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
     */
    bool attachToProcess(pid_t pid);
    
    /**
     * @brief Detach from the current process and clean up resources
     */
    void detachFromProcess();
    
    /**
     * @brief Get information about the currently attached process
     * @return ProcessInfo Complete information about attached process
     */
    [[nodiscard]] ProcessInfo getCurrentProcess() const;
    
    /**
     * @brief Validate that a process is owned by the current user
     * @param pid Process ID to validate
     * @return true if process is owned by current user
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
     */
    [[nodiscard]] SecurityContext getSecurityContext() const;
    
    /**
     * @brief Get human-readable description of an attachment error
     * @param error AttachmentError to describe
     * @return std::string Detailed description of the error
     */
    [[nodiscard]] std::string getErrorDescription(AttachmentError error) const;
    
    /**
     * @brief Get security guidance for resolving access issues
     * @return std::string Detailed guidance for security configuration
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
     */
    [[nodiscard]] bool isProcessAlive(pid_t pid) const;
    
    /**
     * @brief Validate that the current process attachment is still valid
     * @return true if attachment is valid and process is accessible
     */
    [[nodiscard]] bool validateCurrentProcess() const;

    /** @brief Attaches to a process using the legacy API. */
    bool attach(pid_t pid) { return attachToProcess(pid); }
    /** @brief Detaches from the current process using the legacy API. */
    void detach() { detachFromProcess(); }
    /** @brief Returns the current process info as an optional. */
    [[nodiscard]] std::optional<ProcessInfo> currentProcess() const noexcept;
    /** @brief Returns whether the current user owns the process. */
    [[nodiscard]] bool ownsProcess(pid_t pid) const { return validateProcessOwnership(pid); }
    /** @brief Returns the last error string. */
    [[nodiscard]] const std::string& lastError() const noexcept { return last_error_string_; }
    /** @brief Returns the last Mach error code. */
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
