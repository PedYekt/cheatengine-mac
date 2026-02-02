#pragma once

#include <mach/mach.h>
#include <chrono>
#include <memory>
#include <optional>
#include <string>

namespace cheatengine {

class SecurityManager;

class ProcessManager {
public:
    ProcessManager();
    ~ProcessManager();

    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;
    ProcessManager(ProcessManager&&) = default;
    ProcessManager& operator=(ProcessManager&&) = default;

    enum class AttachmentError {
        SUCCESS, INVALID_PID, PERMISSION_DENIED, MISSING_ENTITLEMENTS,
        SIP_PROTECTED, PROCESS_NOT_FOUND, TASK_PORT_FAILED
    };

    enum class ProcessState { DETACHED, ATTACHING, ATTACHED, DETACHING, ERROR_STATE };

    struct ProcessInfo {
        pid_t pid{0};
        std::string executable_path;
        task_t task_port{MACH_PORT_NULL};
        bool is_attached{false};
        bool has_full_access{false};
        ProcessState state{ProcessState::DETACHED};
        std::chrono::steady_clock::time_point attach_time;
    };

    struct SecurityContext {
        bool has_get_task_allow{false};
        bool is_code_signed{false};
        bool sip_enabled{false};
        std::string entitlements_status;
    };

    bool attachToProcess(pid_t pid);
    void detachFromProcess();
    ProcessInfo getCurrentProcess() const;
    bool validateProcessOwnership(pid_t pid) const;
    AttachmentError getLastError() const { return last_error_; }
    SecurityContext getSecurityContext() const;
    std::string getErrorDescription(AttachmentError error) const;
    std::string getSecurityGuidance() const;
    ProcessState getCurrentState() const { return current_process_.state; }
    bool isProcessAlive(pid_t pid) const;
    bool validateCurrentProcess() const;

    bool attach(pid_t pid) { return attachToProcess(pid); }
    void detach() { detachFromProcess(); }
    std::optional<ProcessInfo> currentProcess() const noexcept;
    bool ownsProcess(pid_t pid) const { return validateProcessOwnership(pid); }
    const std::string& lastError() const noexcept { return last_error_string_; }
    int lastMachError() const noexcept { return last_mach_error_; }

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
