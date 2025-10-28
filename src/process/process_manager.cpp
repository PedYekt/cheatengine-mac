#include "cheatengine/process/process_manager.hpp"
#include "cheatengine/process/security_manager.hpp"

#include <errno.h>
#include <signal.h>
#include <sys/sysctl.h>

#include <libproc.h>        // proc_pidinfo / proc_pidpath
#include <mach/mach_error.h>
#include <mach/mach_init.h> // mach_task_self
#include <mach/task.h>      // task_for_pid
#include <sys/proc_info.h>  // PROC_PIDTBSDINFO constants
#include <unistd.h>         // getuid

#include <sstream>

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
        last_error_string_ = "PID must be greater than zero.";
        current_process_.state = ProcessState::ERROR_STATE;
        return false;
    }

    // Set state to attaching
    current_process_.state = ProcessState::ATTACHING;

    if (current_process_.is_attached) {
        detachFromProcess();
    }

    // Check if process exists and is owned by current user
    if (!validateProcessOwnership(pid)) {
        last_error_ = AttachmentError::PERMISSION_DENIED;
        last_error_string_ = "Process is not owned by the current user or is inaccessible.";
        current_process_.state = ProcessState::ERROR_STATE;
        return false;
    }

    // Use SecurityManager to evaluate process access
    auto access_info = security_manager_->evaluateProcessAccess(pid);
    
    if (access_info.level == SecurityManager::AccessLevel::NO_ACCESS) {
        if (access_info.restriction_reason.find("System Integrity Protection") != std::string::npos) {
            last_error_ = AttachmentError::SIP_PROTECTED;
        } else if (access_info.restriction_reason.find("not owned") != std::string::npos) {
            last_error_ = AttachmentError::PERMISSION_DENIED;
        } else if (access_info.restriction_reason.find("not found") != std::string::npos) {
            last_error_ = AttachmentError::PROCESS_NOT_FOUND;
        } else {
            last_error_ = AttachmentError::PERMISSION_DENIED;
        }
        last_error_string_ = access_info.restriction_reason;
        current_process_.state = ProcessState::ERROR_STATE;
        return false;
    }

    // Try to acquire task port
    task_t task = MACH_PORT_NULL;
    if (!acquireTaskPort(pid, task)) {
        // Task port acquisition failed, but we can still provide limited access
        ProcessInfo info;
        info.pid = pid;
        info.task_port = MACH_PORT_NULL;
        info.is_attached = true;
        info.has_full_access = false;
        info.state = ProcessState::ATTACHED;
        info.attach_time = std::chrono::steady_clock::now();

        // Get executable path using proc APIs
        char path_buffer[PROC_PIDPATHINFO_MAXSIZE] = {};
        const int path_length = proc_pidpath(pid, path_buffer, sizeof(path_buffer));
        if (path_length > 0) {
            info.executable_path.assign(path_buffer, static_cast<size_t>(path_length));
        }

        current_process_ = std::move(info);
        
        // Set appropriate error but still return success for limited access
        if (last_mach_error_ == 5) { // KERN_FAILURE often indicates missing entitlements
            last_error_ = AttachmentError::MISSING_ENTITLEMENTS;
        } else {
            last_error_ = AttachmentError::TASK_PORT_FAILED;
        }
        
        return true; // Limited access is still considered successful attachment
    }

    // Full access with task port
    ProcessInfo info;
    info.pid = pid;
    info.task_port = task;
    info.is_attached = true;
    info.has_full_access = true;
    info.state = ProcessState::ATTACHED;
    info.attach_time = std::chrono::steady_clock::now();

    // Get executable path
    char path_buffer[PROC_PIDPATHINFO_MAXSIZE] = {};
    const int path_length = proc_pidpath(pid, path_buffer, sizeof(path_buffer));
    if (path_length > 0) {
        info.executable_path.assign(path_buffer, static_cast<size_t>(path_length));
    }

    current_process_ = std::move(info);
    last_error_ = AttachmentError::SUCCESS;
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
    if (current_process_.is_attached) {
        return current_process_;
    }
    return std::nullopt;
}

bool ProcessManager::validateProcessOwnership(pid_t pid) const
{
    if (pid <= 0) {
        return false; // invalid PID
    }

    struct proc_bsdinfo info {};
    errno = 0;
    const int result =
        proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, PROC_PIDTBSDINFO_SIZE);

    if (result == PROC_PIDTBSDINFO_SIZE) {
        const uid_t current_uid = getuid();
        return info.pbi_uid == current_uid;
    }

    if (result == -1) {
        if (errno == ESRCH) {
            return false; // Process not found
        }
        if (errno == EPERM || errno == EACCES) {
            // Try alternative methods for process validation
            char path_buffer[PROC_PIDPATHINFO_MAXSIZE] = {};
            if (proc_pidpath(pid, path_buffer, sizeof(path_buffer)) > 0) {
                return true;
            }
            if (kill(pid, 0) == 0) {
                return true;
            }
        }
    }

    // As a final fallback, allow access if we can signal the process
    if (kill(pid, 0) == 0) {
        return true;
    }

    return false;
}

bool ProcessManager::acquireTaskPort(pid_t pid, task_t& task_port)
{
    task_port = MACH_PORT_NULL;

    const kern_return_t kr = task_for_pid(mach_task_self(), pid, &task_port);

    if (kr != KERN_SUCCESS) {
        task_port = MACH_PORT_NULL;
        last_mach_error_ = kr;
        const char* mach_message = mach_error_string(kr);
        std::ostringstream oss;
        oss << "task_for_pid(" << pid << ") failed with error " << kr;
        if (mach_message != nullptr) {
            oss << " (" << mach_message << ")";
        }
        last_error_string_ = oss.str();
        return false;
    }

    last_error_string_.clear();
    last_mach_error_ = 0;
    return true;
}

bool ProcessManager::checkEntitlements() const
{
    // This is a simplified check - in a real implementation, you would
    // parse the current executable's entitlements using Security framework
    // For now, we'll assume entitlements are present if we can call task_for_pid
    // on our own process successfully
    task_t self_task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &self_task);
    
    if (kr == KERN_SUCCESS && self_task != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), self_task);
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
    SecurityContext context;
    
    // Check if we have get-task-allow entitlement
    context.has_get_task_allow = checkEntitlements();
    
    // Check if binary is code signed (simplified check)
    context.is_code_signed = true; // Assume signed for now
    
    // Check SIP status
    int sip_status = 0;
    size_t size = sizeof(sip_status);
    context.sip_enabled = (sysctlbyname("kern.sip_status", &sip_status, &size, nullptr, 0) == 0 && sip_status != 0);
    
    // Set entitlements status
    if (context.has_get_task_allow) {
        context.entitlements_status = "Required entitlements present";
    } else {
        context.entitlements_status = "Missing com.apple.security.get-task-allow entitlement";
    }
    
    return context;
}

std::string ProcessManager::getErrorDescription(AttachmentError error) const
{
    switch (error) {
        case AttachmentError::SUCCESS:
            return "No error";
        case AttachmentError::INVALID_PID:
            return "Invalid process ID provided";
        case AttachmentError::PERMISSION_DENIED:
            return "Permission denied - process not owned by current user";
        case AttachmentError::MISSING_ENTITLEMENTS:
            return "Missing required entitlements (com.apple.security.get-task-allow)";
        case AttachmentError::SIP_PROTECTED:
            return "Process is protected by System Integrity Protection";
        case AttachmentError::PROCESS_NOT_FOUND:
            return "Process not found or has terminated";
        case AttachmentError::TASK_PORT_FAILED:
            return "Failed to acquire task port for process";
        default:
            return "Unknown error";
    }
}

std::string ProcessManager::getSecurityGuidance() const
{
    return security_manager_->getEntitlementsGuidance();
}

bool ProcessManager::isProcessAlive(pid_t pid) const
{
    if (pid <= 0) {
        return false;
    }
    
    // Use kill with signal 0 to check if process exists
    return kill(pid, 0) == 0;
}

bool ProcessManager::validateCurrentProcess() const
{
    if (!current_process_.is_attached) {
        return false;
    }
    
    // Check if the process is still alive
    if (!isProcessAlive(current_process_.pid)) {
        return false;
    }
    
    // If we have a task port, validate it's still valid
    if (current_process_.has_full_access && current_process_.task_port != MACH_PORT_NULL) {
        // Try a simple mach call to validate the port
        mach_port_type_t port_type;
        kern_return_t kr = mach_port_type(mach_task_self(), current_process_.task_port, &port_type);
        return kr == KERN_SUCCESS;
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
