/**
 * @file errors.hpp
 * @brief Comprehensive error handling system for CheatEngine
 * 
 * This file demonstrates modern C++ exception handling patterns and provides
 * educational examples of how to build robust error handling for system programming.
 * 
 * Educational Focus:
 * - Exception hierarchy design
 * - System error code integration
 * - Recoverable vs. non-recoverable error classification
 * - Error message formatting and user guidance
 * - Mach kernel error handling patterns
 */

#pragma once

#include <mach/kern_return.h>
#include <stdexcept>
#include <string>
#include <sys/types.h>

namespace cheatengine {

/**
 * @brief Base exception class for all CheatEngine errors
 * 
 * This class demonstrates how to build a comprehensive exception hierarchy
 * that integrates with system error codes while providing educational
 * information about the underlying system concepts.
 * 
 * Educational Concepts:
 * - Exception hierarchy design patterns
 * - System error code preservation and translation
 * - Error categorization for different handling strategies
 * - Integration of C-style error codes with C++ exceptions
 * 
 * Design Principles:
 * - Preserve original system error information
 * - Provide human-readable error descriptions
 * - Enable programmatic error handling through categorization
 * - Support both technical and user-friendly error reporting
 */
class CheatEngineException : public std::runtime_error {
public:
    /**
     * @brief Error type categories for programmatic handling
     * 
     * These categories help determine appropriate error handling strategies
     * and provide educational insight into different types of system failures.
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
     * 
     * Educational Note: This constructor demonstrates how to preserve both
     * high-level error categorization and low-level system error details
     * for comprehensive error reporting.
     */
    CheatEngineException(ErrorType type, std::string message, int system_error = 0);

    /**
     * @brief Get the error type category
     * @return ErrorType The category of this error
     * 
     * Enables programmatic error handling based on error category.
     * Educational Note: Shows how to enable different handling strategies
     * for different types of system failures.
     */
    [[nodiscard]] ErrorType type() const noexcept { return type_; }
    
    /**
     * @brief Get the underlying system error code
     * @return int System error code (0 if no system error)
     * 
     * Provides access to the original system error for detailed debugging.
     * Educational Note: Demonstrates preservation of low-level error information
     * for system programming diagnostics.
     */
    [[nodiscard]] int systemError() const noexcept { return system_error_; }
    
    /**
     * @brief Get a human-readable string for the error type
     * @return std::string Description of the error category
     * 
     * Provides user-friendly error type descriptions for educational purposes.
     */
    [[nodiscard]] std::string getErrorTypeString() const;
    
    /**
     * @brief Determine if this error might be recoverable
     * @return true if the error might be recoverable with retry or user action
     * 
     * Educational Note: Demonstrates error classification for building
     * resilient systems that can handle transient failures appropriately.
     */
    [[nodiscard]] bool isRecoverable() const noexcept;

private:
    ErrorType type_;        ///< High-level error category
    int system_error_;      ///< Low-level system error code
};

/**
 * @brief Specialized exception for process attachment failures
 * 
 * This class demonstrates how to create domain-specific exceptions that provide
 * detailed context and actionable solutions for specific types of failures.
 * It's particularly educational for understanding macOS security mechanisms.
 * 
 * Educational Concepts:
 * - Specialized exception design for specific problem domains
 * - macOS security model integration (SIP, entitlements, code signing)
 * - Actionable error reporting with solution suggestions
 * - Process security boundary understanding
 */
class ProcessAttachmentError : public CheatEngineException {
public:
    /**
     * @brief Specific reasons for process attachment failures
     * 
     * These reasons map directly to macOS security mechanisms and provide
     * educational insight into the system's security architecture.
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
     * 
     * Educational Note: This constructor demonstrates how to capture
     * comprehensive context for domain-specific failures.
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
     * 
     * Educational Note: Demonstrates how to provide educational guidance
     * that helps users understand and resolve system-level issues.
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
 * @return std::string Formatted error message with educational context
 * 
 * This function demonstrates how to translate low-level system error codes
 * into educational, actionable error messages that help users understand
 * the underlying system concepts.
 * 
 * Educational Value:
 * - Maps Mach error codes to human-readable descriptions
 * - Provides context about what each error means
 * - Suggests potential causes and solutions
 */
std::string formatMachError(const char* call, kern_return_t code);

/**
 * @brief Macro for systematic Mach API error checking
 * @param call Mach API function call to check
 * @param error_type CheatEngineException::ErrorType to use for failures
 * 
 * This macro demonstrates a common pattern in system programming for
 * consistent error handling of C-style APIs that return error codes.
 * 
 * Educational Concepts:
 * - Systematic error checking patterns
 * - Integration of C-style error codes with C++ exceptions
 * - Macro-based code generation for repetitive error handling
 * - Preservation of call site information for debugging
 * 
 * Usage Example:
 * @code
 * MACH_CHECK(mach_vm_read_overwrite(task, address, size, buffer, &read_size),
 *            CheatEngineException::ErrorType::MEMORY_OPERATION);
 * @endcode
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
 * 
 * Convenience macro for the most common case of memory operation error checking.
 * Demonstrates how to provide simplified interfaces for common use cases.
 */
#define MACH_CHECK_SIMPLE(call)                                                                    \
    MACH_CHECK(call, ::cheatengine::CheatEngineException::ErrorType::MEMORY_OPERATION)

} // namespace cheatengine
