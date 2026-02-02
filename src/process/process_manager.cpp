#include "cheatengine/process/process_manager.hpp"
#include "cheatengine/process/security_manager.hpp"

#include <errno.h>
#include <signal.h>
#include <sys/sysctl.h>

#include <libproc.h>
#include <mach/mach_error.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#include <sys/proc_info.h>
#include <unistd.h>

namespace cheatengine {

ProcessManager::ProcessManager() : security_manager_(std::make_unique<SecurityManager>()) {}

ProcessManager::~ProcessManager() = default;

bool ProcessManager::attachToProcess(pid_t pid)
{
    last_error_string_.clear();
    last_mach_error_ = 0;
    last_error_ = AttachmentError::SUCCESS;

    if (pid <= 0) {
        last_error_ = AttachmentError::INVALID_PID;
        last_error_string_ = "Invalid PID";
        current_process_.state = ProcessState::ERROR_STATE;
        return false;
    }

    current_process_.state = ProcessState::ATTACHING;

    if (current_process_.is_attached) {
        detachFromProcess();
    }

    if (!validateProcessOwnership(pid)) {
        last_error_ = AttachmentError::PERMISSION_DENIED;
        last_error_string_ = "Not owned by current user";
        current_process_.state = ProcessState::ERROR_STATE;
        return false;
    }

    auto access = security_manager_->evaluateProcessAccess(pid);
    if (access.level == SecurityManager::AccessLevel::NO_ACCESS) {
        last_error_ = AttachmentError::PERMISSION_DENIED;
        last_error_string_ = access.restriction_reason;
        current_process_.state = ProcessState::ERROR_STATE;
        return false;
    }

    task_t task = MACH_PORT_NULL;
    bool has_task = acquireTaskPort(pid, task);

    ProcessInfo info;
    info.pid = pid;
    info.task_port = task;
    info.is_attached = true;
    info.has_full_access = has_task;
    info.state = ProcessState::ATTACHED;
    info.attach_time = std::chrono::steady_clock::now();

    char path[PROC_PIDPATHINFO_MAXSIZE] = {};
    if (proc_pidpath(pid, path, sizeof(path)) > 0) {
        info.executable_path = path;
    }

    current_process_ = info;
    return true;
}

void ProcessManager::detachFromProcess()
{
    if (current_process_.is_attached) {
        current_process_.state = ProcessState::DETACHING;
    }
    resetState();
}

ProcessManager::ProcessInfo ProcessManager::getCurrentProcess() const
{
    return current_process_;
}

std::optional<ProcessManager::ProcessInfo> ProcessManager::currentProcess() const noexcept
{
    if (current_process_.is_attached) return current_process_;
    return std::nullopt;
}

bool ProcessManager::validateProcessOwnership(pid_t pid) const
{
    if (pid <= 0) return false;

    struct proc_bsdinfo info{};
    int result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, PROC_PIDTBSDINFO_SIZE);

    if (result == PROC_PIDTBSDINFO_SIZE) {
        return info.pbi_uid == getuid();
    }

    return kill(pid, 0) == 0;
}

bool ProcessManager::acquireTaskPort(pid_t pid, task_t& task_port)
{
    task_port = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task_port);

    if (kr != KERN_SUCCESS) {
        task_port = MACH_PORT_NULL;
        last_mach_error_ = kr;
        last_error_string_ = "task_for_pid failed: " + std::to_string(kr);
        return false;
    }

    return true;
}

bool ProcessManager::checkEntitlements() const
{
    task_t self = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &self);

    if (kr == KERN_SUCCESS && self != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), self);
        return true;
    }
    return false;
}

bool ProcessManager::isSystemProcess(pid_t pid) const
{
    return security_manager_->isSystemProcess(pid);
}

bool ProcessManager::isSIPProtected(pid_t pid) const
{
    return security_manager_->isSIPProtected(pid);
}

ProcessManager::SecurityContext ProcessManager::getSecurityContext() const
{
    SecurityContext ctx;
    ctx.has_get_task_allow = checkEntitlements();
    ctx.is_code_signed = true;

    int sip = 0;
    size_t size = sizeof(sip);
    ctx.sip_enabled = (sysctlbyname("kern.sip_status", &sip, &size, nullptr, 0) == 0 && sip != 0);
    ctx.entitlements_status = ctx.has_get_task_allow ? "OK" : "Missing get-task-allow";

    return ctx;
}

std::string ProcessManager::getErrorDescription(AttachmentError error) const
{
    switch (error) {
        case AttachmentError::SUCCESS: return "OK";
        case AttachmentError::INVALID_PID: return "Invalid PID";
        case AttachmentError::PERMISSION_DENIED: return "Permission denied";
        case AttachmentError::MISSING_ENTITLEMENTS: return "Missing entitlements";
        case AttachmentError::SIP_PROTECTED: return "SIP protected";
        case AttachmentError::PROCESS_NOT_FOUND: return "Process not found";
        case AttachmentError::TASK_PORT_FAILED: return "Task port failed";
        default: return "Unknown";
    }
}

std::string ProcessManager::getSecurityGuidance() const
{
    return "Sign with com.apple.security.get-task-allow entitlement.";
}

bool ProcessManager::isProcessAlive(pid_t pid) const
{
    return pid > 0 && kill(pid, 0) == 0;
}

bool ProcessManager::validateCurrentProcess() const
{
    if (!current_process_.is_attached) return false;
    if (!isProcessAlive(current_process_.pid)) return false;

    if (current_process_.has_full_access && current_process_.task_port != MACH_PORT_NULL) {
        mach_port_type_t type;
        return mach_port_type(mach_task_self(), current_process_.task_port, &type) == KERN_SUCCESS;
    }

    return true;
}

void ProcessManager::resetState()
{
    if (current_process_.task_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), current_process_.task_port);
    }
    current_process_ = {};
    current_process_.state = ProcessState::DETACHED;
    last_error_ = AttachmentError::SUCCESS;
    last_error_string_.clear();
    last_mach_error_ = 0;
}

} // namespace cheatengine
