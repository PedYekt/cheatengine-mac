#include "cheatengine/core/errors.hpp"

#include <mach/mach_error.h>

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
        case ErrorType::PROCESS_ACCESS: return "Process Access Error";
        case ErrorType::MEMORY_OPERATION: return "Memory Operation Error";
        case ErrorType::SYSTEM_RESOURCE: return "System Resource Error";
        case ErrorType::INVALID_PARAMETER: return "Invalid Parameter Error";
        case ErrorType::SECURITY_VIOLATION: return "Security Violation Error";
        case ErrorType::PERMISSION_DENIED: return "Permission Denied Error";
        case ErrorType::INVALID_ADDRESS: return "Invalid Address Error";
        default: return "Unknown Error";
    }
}

bool CheatEngineException::isRecoverable() const noexcept
{
    switch (type_) {
        case ErrorType::INVALID_PARAMETER:
        case ErrorType::INVALID_ADDRESS:
        case ErrorType::SYSTEM_RESOURCE:
            return true;
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
        case Reason::MISSING_ENTITLEMENTS: return "Code sign with com.apple.security.get-task-allow";
        case Reason::SIP_PROTECTED: return "Cannot attach to SIP-protected processes";
        case Reason::INVALID_CODE_SIGNATURE: return "Ensure proper code signing";
        case Reason::PROCESS_NOT_OWNED: return "Can only attach to processes you own";
        case Reason::SYSTEM_PROCESS_BLOCKED: return "System processes are protected";
        case Reason::PROCESS_NOT_FOUND: return "Process not found";
        default: return "Unknown error";
    }
}

std::string formatMachError(const char* call, kern_return_t code)
{
    std::string msg = std::string(call) + " failed: " + std::to_string(code);
    const char* mach_msg = mach_error_string(code);
    if (mach_msg) {
        msg += " (" + std::string(mach_msg) + ")";
    }
    return msg;
}

} // namespace cheatengine
