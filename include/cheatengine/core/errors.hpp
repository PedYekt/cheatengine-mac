#pragma once

#include <mach/kern_return.h>
#include <stdexcept>
#include <string>
#include <sys/types.h>

namespace cheatengine {

class CheatEngineException : public std::runtime_error {
public:
    enum class ErrorType {
        PROCESS_ACCESS,
        MEMORY_OPERATION,
        SYSTEM_RESOURCE,
        INVALID_PARAMETER,
        SECURITY_VIOLATION,
        PERMISSION_DENIED,
        INVALID_ADDRESS
    };

    CheatEngineException(ErrorType type, std::string message, int system_error = 0);

    ErrorType type() const noexcept { return type_; }
    int systemError() const noexcept { return system_error_; }
    std::string getErrorTypeString() const;
    bool isRecoverable() const noexcept;

private:
    ErrorType type_;
    int system_error_;
};

class ProcessAttachmentError : public CheatEngineException {
public:
    enum class Reason {
        MISSING_ENTITLEMENTS,
        SIP_PROTECTED,
        INVALID_CODE_SIGNATURE,
        PROCESS_NOT_OWNED,
        SYSTEM_PROCESS_BLOCKED,
        PROCESS_NOT_FOUND
    };

    ProcessAttachmentError(Reason reason, pid_t pid, const std::string& details);

    Reason getReason() const noexcept { return reason_; }
    pid_t getTargetPid() const noexcept { return target_pid_; }
    std::string getSolution() const;

private:
    Reason reason_;
    pid_t target_pid_;
};

std::string formatMachError(const char* call, kern_return_t code);

} // namespace cheatengine
