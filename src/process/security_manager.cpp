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
        info.restriction_reason = "Invalid process ID";
        info.suggested_solutions.push_back("Provide a valid process ID greater than 0");
        return info;
    }
    
    // Check if process exists and get basic info
    struct proc_bsdinfo proc_info {};
    int result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &proc_info, PROC_PIDTBSDINFO_SIZE);
    
    if (result != PROC_PIDTBSDINFO_SIZE) {
        if (errno == ESRCH) {
            info.restriction_reason = "Process not found or has terminated";
            info.suggested_solutions.push_back("Verify the process is still running");
            info.suggested_solutions.push_back("Check the process ID is correct");
        } else {
            info.restriction_reason = "Cannot access process information";
            info.suggested_solutions.push_back("Check if process exists and is accessible");
        }
        return info;
    }
    
    // Check process ownership
    uid_t current_uid = getuid();
    if (proc_info.pbi_uid != current_uid) {
        info.restriction_reason = "Process is not owned by current user";
        info.suggested_solutions.push_back("Only processes owned by your user can be accessed");
        info.suggested_solutions.push_back("Run as the process owner or use sudo if appropriate");
        return info;
    }
    
    // At this point we have at least limited access
    info.level = AccessLevel::LIMITED_ACCESS;
    
    // Check if it's a system process
    if (isSystemProcess(pid)) {
        if (isSIPProtected(pid)) {
            info.restriction_reason = "System process protected by SIP";
            info.suggested_solutions.push_back("System processes are protected by System Integrity Protection");
            info.suggested_solutions.push_back("Disable SIP in Recovery Mode (not recommended for security)");
            info.suggested_solutions.push_back("Use user processes instead of system processes");
            return info;
        }
    }
    
    // Try to get task port to determine full access
    task_t task_port = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task_port);
    
    if (kr == KERN_SUCCESS && task_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), task_port);
        info.level = AccessLevel::FULL_ACCESS;
        info.restriction_reason = "Full access available";
        return info;
    }
    
    // Task port failed, analyze why
    if (kr == KERN_FAILURE || kr == 5) { // Common error codes for missing entitlements
        info.restriction_reason = "Missing required entitlements for task_for_pid";
        info.suggested_solutions.push_back("Add com.apple.security.get-task-allow entitlement");
        info.suggested_solutions.push_back("Code sign the application with proper entitlements");
        info.suggested_solutions.push_back("Use Xcode or codesign command with entitlements file");
        info.suggested_solutions.push_back("Limited functionality available using proc APIs");
    } else {
        info.restriction_reason = "Task port acquisition failed";
        info.suggested_solutions.push_back("Check code signing and entitlements");
        info.suggested_solutions.push_back("Verify the target process is accessible");
        info.suggested_solutions.push_back("Limited functionality available using proc APIs");
    }
    
    return info;
}

bool SecurityManager::isSystemProcess(pid_t pid)
{
    // System processes typically have low PIDs
    if (pid < SYSTEM_PROCESS_PID_THRESHOLD) {
        return true;
    }
    
    // Check if owned by root
    struct proc_bsdinfo info {};
    int result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, PROC_PIDTBSDINFO_SIZE);
    
    if (result == PROC_PIDTBSDINFO_SIZE) {
        return info.pbi_uid == 0; // root owned
    }
    
    return false;
}

bool SecurityManager::isSIPProtected(pid_t pid)
{
    // First check if SIP is enabled system-wide
    if (!checkSIPStatus()) {
        return false; // SIP is disabled
    }
    
    // If SIP is enabled and it's a system process, it's likely protected
    if (isSystemProcess(pid)) {
        return true;
    }
    
    // Additional checks could be added here for specific SIP-protected paths
    // For now, we'll be conservative and assume system processes are protected
    return false;
}

std::string SecurityManager::getEntitlementsGuidance()
{
    std::string guidance = "To enable full memory access, your application needs proper entitlements:\n\n";
    
    guidance += "1. Create an entitlements file (debug-entitlements.plist):\n";
    guidance += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    guidance += "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
    guidance += "<plist version=\"1.0\">\n";
    guidance += "<dict>\n";
    guidance += "    <key>com.apple.security.get-task-allow</key>\n";
    guidance += "    <true/>\n";
    guidance += "    <key>com.apple.security.cs.debugger</key>\n";
    guidance += "    <true/>\n";
    guidance += "</dict>\n";
    guidance += "</plist>\n\n";
    
    guidance += "2. Code sign your application:\n";
    guidance += "codesign --force --sign \"Apple Development\" --entitlements debug-entitlements.plist your_app\n\n";
    
    guidance += "3. Or configure CMake for automatic code signing:\n";
    guidance += "set_target_properties(your_target PROPERTIES\n";
    guidance += "    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS \"debug-entitlements.plist\"\n";
    guidance += "    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY \"Apple Development\"\n";
    guidance += ")\n\n";
    
    guidance += "Note: Even without full access, basic process information is available using proc APIs.";
    
    return guidance;
}

bool SecurityManager::checkSIPStatus()
{
    int sip_status = 0;
    size_t size = sizeof(sip_status);
    
    if (sysctlbyname("kern.sip_status", &sip_status, &size, nullptr, 0) == 0) {
        return sip_status != 0; // Non-zero means SIP is enabled
    }
    
    // If we can't determine SIP status, assume it's enabled for safety
    return true;
}

bool SecurityManager::validateCodeSigning()
{
    // This is a simplified implementation
    // In a real application, you would use the Security framework
    // to validate the code signature and entitlements
    
    // For now, we'll do a basic check by trying task_for_pid on ourselves
    task_t self_task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), getpid(), &self_task);
    
    if (kr == KERN_SUCCESS && self_task != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), self_task);
        return true;
    }
    
    return false;
}

} // namespace cheatengine