#include "cheatengine/core/errors.hpp"

#include <mach/mach_error.h>
#include <sstream>



namespace cheatengine {

CheatEngineException::CheatEngineException(ErrorType type, std::string message, int system_error)
    : std::runtime_error(std::move(message))
    , type_(type)
    , system_error_(system_error)
{
}

std::string CheatEngineException::getErrorTypeString() const
{
    switch (type_) {
        case ErrorType::PROCESS_ACCESS:
            return "Process Access Error";
        case ErrorType::MEMORY_OPERATION:
            return "Memory Operation Error";
        case ErrorType::SYSTEM_RESOURCE:
            return "System Resource Error";
        case ErrorType::INVALID_PARAMETER:
            return "Invalid Parameter Error";
        case ErrorType::SECURITY_VIOLATION:
            return "Security Violation Error";
        case ErrorType::PERMISSION_DENIED:
            return "Permission Denied Error";
        case ErrorType::INVALID_ADDRESS:
            return "Invalid Address Error";
        default:
            return "Unknown Error";
    }
}

bool CheatEngineException::isRecoverable() const noexcept
{
    switch (type_) {
        case ErrorType::INVALID_PARAMETER:
        case ErrorType::INVALID_ADDRESS:
            return true;  // User can correct these
        case ErrorType::PROCESS_ACCESS:
        case ErrorType::MEMORY_OPERATION:
            return false; // Usually require process restart or different approach
        case ErrorType::SYSTEM_RESOURCE:
            return true;  // Might be temporary
        case ErrorType::SECURITY_VIOLATION:
        case ErrorType::PERMISSION_DENIED:
            return false; // Require system-level changes
        default:
            return false;
    }
}

ProcessAttachmentError::ProcessAttachmentError(Reason reason, pid_t pid, const std::string& details)
    : CheatEngineException(ErrorType::PROCESS_ACCESS, details, 0)
    , reason_(reason)
    , target_pid_(pid)
{
}

std::string ProcessAttachmentError::getSolution() const
{
    switch (reason_) {
        case Reason::MISSING_ENTITLEMENTS:
            return "Code sign the application with proper entitlements (com.apple.security.get-task-allow)";
        case Reason::SIP_PROTECTED:
            return "Cannot attach to system processes protected by SIP. Try a user process instead";
        case Reason::INVALID_CODE_SIGNATURE:
            return "Ensure the application is properly code signed for debugging";
        case Reason::PROCESS_NOT_OWNED:
            return "Can only attach to processes owned by the current user";
        case Reason::SYSTEM_PROCESS_BLOCKED:
            return "System processes are protected. Use a user application for testing";
        case Reason::PROCESS_NOT_FOUND:
            return "Verify the process ID is correct and the process is still running";
        default:
            return "Unknown attachment error";
    }
}
std::string formatMachError(const char* call, kern_return_t code)
{
    const char* mach_message = mach_error_string(code);

    std::ostringstream oss;
    oss << call << " failed with error " << code;
    if (mach_message != nullptr) {
        oss << " (" << mach_message << ')';
    }
    return oss.str();
}

} // namespace cheatengine
