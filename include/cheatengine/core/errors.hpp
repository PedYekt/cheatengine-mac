/**
 * @file errors.hpp
 * @brief Comprehensive error handling system for CheatEngine
 */

#pragma once

#include <mach/kern_return.h>
#include <stdexcept>
#include <string>
#include <sys/types.h>

namespace cheatengine {

/**
 * @brief Base exception class for all CheatEngine errors
 */
class CheatEngineException : public std::runtime_error {
public:
    /**
     * @brief Error type categories for programmatic handling
     */
    enum class ErrorType {
        PROCESS_ACCESS,      ///< Process attachment, validation, or access failures
        MEMORY_OPERATION,    ///< Memory reading, writing, or mapping failures  
        SYSTEM_RESOURCE,     ///< System resource exhaustion or allocation failures
        INVALID_PARAMETER,   ///< Invalid input parameters or configuration
        SECURITY_VIOLATION,  ///< Security policy violations or permission issues
        PERMISSION_DENIED,   ///< Explicit permission denials from the system
        INVALID_ADDRESS      ///< Invalid memory addresses or region access
    };

    /**
     * @brief Construct a CheatEngine exception
     * @param type Category of error for programmatic handling
     * @param message Human-readable error description
     * @param system_error Optional system error code (errno, Mach error, etc.)
     */
    CheatEngineException(ErrorType type, std::string message, int system_error = 0);

    /**
     * @brief Get the error type category
     * @return ErrorType The category of this error
     */
    [[nodiscard]] ErrorType type() const noexcept { return type_; }
    
    /**
     * @brief Get the underlying system error code
     * @return int System error code (0 if no system error)
     */
    [[nodiscard]] int systemError() const noexcept { return system_error_; }
    
    /**
     * @brief Get a human-readable string for the error type
     * @return std::string Description of the error category
     */
    [[nodiscard]] std::string getErrorTypeString() const;
    
    /**
     * @brief Determine if this error might be recoverable
     * @return true if the error might be recoverable with retry or user action
     */
    [[nodiscard]] bool isRecoverable() const noexcept;

private:
    ErrorType type_;        ///< High-level error category
    int system_error_;      ///< Low-level system error code
};

/**
 * @brief Specialized exception for process attachment failures
 */
class ProcessAttachmentError : public CheatEngineException {
public:
    /**
     * @brief Specific reasons for process attachment failures
     */
    enum class Reason {
        MISSING_ENTITLEMENTS,      ///< Required entitlements not present in code signature
        SIP_PROTECTED,             ///< System Integrity Protection blocks access
        INVALID_CODE_SIGNATURE,    ///< Code signature invalid or missing
        PROCESS_NOT_OWNED,         ///< Process owned by different user
        SYSTEM_PROCESS_BLOCKED,    ///< System process access restricted
        PROCESS_NOT_FOUND          ///< Process ID does not exist
    };

    /**
     * @brief Construct a process attachment error
     * @param reason Specific reason for the attachment failure
     * @param pid Process ID that failed to attach
     * @param details Additional technical details about the failure
     */
    ProcessAttachmentError(Reason reason, pid_t pid, const std::string& details);
    
    /**
     * @brief Get the specific reason for attachment failure
     * @return Reason The specific cause of the failure
     */
    [[nodiscard]] Reason getReason() const noexcept { return reason_; }
    
    /**
     * @brief Get the process ID that failed to attach
     * @return pid_t The target process ID
     */
    [[nodiscard]] pid_t getTargetPid() const noexcept { return target_pid_; }
    
    /**
     * @brief Get actionable solution suggestions
     * @return std::string Detailed steps to resolve the issue
     */
    [[nodiscard]] std::string getSolution() const;

private:
    Reason reason_;         ///< Specific failure reason
    pid_t target_pid_;      ///< Target process ID
};

/**
 * @brief Format Mach kernel error codes into human-readable messages
 * @param call Name of the Mach API call that failed
 * @param code Mach kernel return code
 * @return std::string Formatted error message with detailed context
 */
std::string formatMachError(const char* call, kern_return_t code);

/**
 * @brief Macro for systematic Mach API error checking
 * @param call Mach API function call to check
 * @param error_type CheatEngineException::ErrorType to use for failures
 */
#define MACH_CHECK(call, error_type)                                                                \
    do {                                                                                            \
        kern_return_t kr__ = (call);                                                                \
        if (kr__ != KERN_SUCCESS) {                                                                 \
            throw ::cheatengine::CheatEngineException(                                              \
                (error_type),                                                                       \
                ::cheatengine::formatMachError(#call, kr__),                                        \
                static_cast<int>(kr__));                                                            \
        }                                                                                           \
    } while (0)

/**
 * @brief Simplified MACH_CHECK that defaults to MEMORY_OPERATION error type
 * @param call Mach API function call to check
 */
#define MACH_CHECK_SIMPLE(call)                                                                    \
    MACH_CHECK(call, ::cheatengine::CheatEngineException::ErrorType::MEMORY_OPERATION)

} // namespace cheatengine
