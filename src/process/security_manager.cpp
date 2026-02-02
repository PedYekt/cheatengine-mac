#include "cheatengine/process/security_manager.hpp"

#include <errno.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <libproc.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#include <sys/proc_info.h>

namespace cheatengine {

SecurityManager::ProcessAccessInfo SecurityManager::evaluateProcessAccess(pid_t pid)
{
    ProcessAccessInfo info;
    info.level = AccessLevel::NO_ACCESS;

    if (pid <= 0) {
        info.restriction_reason = "Invalid PID";
        return info;
    }

    struct proc_bsdinfo proc_info {};
    int result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &proc_info, PROC_PIDTBSDINFO_SIZE);

    if (result != PROC_PIDTBSDINFO_SIZE) {
        info.restriction_reason = (errno == ESRCH) ? "Process not found" : "Cannot access process";
        return info;
    }

    if (proc_info.pbi_uid != getuid()) {
        info.restriction_reason = "Process not owned by current user";
        return info;
    }

    info.level = AccessLevel::LIMITED_ACCESS;

    if (isSystemProcess(pid) && isSIPProtected(pid)) {
        info.restriction_reason = "SIP protected";
        return info;
    }

    task_t task_port = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task_port);

    if (kr == KERN_SUCCESS && task_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), task_port);
        info.level = AccessLevel::FULL_ACCESS;
        info.restriction_reason.clear();
        return info;
    }

    info.restriction_reason = "Missing entitlements";
    return info;
}

bool SecurityManager::isSystemProcess(pid_t pid)
{
    if (pid < SYSTEM_PROCESS_PID_THRESHOLD) return true;

    struct proc_bsdinfo info {};
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, PROC_PIDTBSDINFO_SIZE) == PROC_PIDTBSDINFO_SIZE) {
        return info.pbi_uid == 0;
    }

    return false;
}

bool SecurityManager::isSIPProtected(pid_t pid)
{
    if (!checkSIPStatus()) return false;
    return isSystemProcess(pid);
}

bool SecurityManager::checkSIPStatus()
{
    int sip_status = 0;
    size_t size = sizeof(sip_status);

    if (sysctlbyname("kern.sip_status", &sip_status, &size, nullptr, 0) == 0) {
        return sip_status != 0;
    }

    return true;
}

bool SecurityManager::validateCodeSigning()
{
    task_t self_task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &self_task);

    if (kr == KERN_SUCCESS && self_task != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), self_task);
        return true;
    }

    return false;
}

} // namespace cheatengine
