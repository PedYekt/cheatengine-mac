/**
 * @file security_manager.hpp
 * @brief macOS security model integration and validation
 */

#pragma once

#include <mach/mach.h>
#include <string>
#include <vector>

namespace cheatengine {

/**
 * @brief macOS security model integration and process access validation
 */
class SecurityManager {
public:
    /**
     * @brief Levels of access available for process interaction
     */
    enum class AccessLevel {
        FULL_ACCESS,        ///< Has task port, can read/write memory freely
        LIMITED_ACCESS,     ///< Can use proc APIs, basic info only
        NO_ACCESS          ///< Cannot access process at all due to restrictions
    };
    
    /**
     * @brief Comprehensive process access evaluation result
     */
    struct ProcessAccessInfo {
        AccessLevel level;                              ///< Determined access level
        std::string restriction_reason;                 ///< Explanation of any restrictions
        std::vector<std::string> suggested_solutions;   ///< Actionable steps to resolve issues
    };

    /**
     * @brief Evaluate available access level for a specific process
     * @param pid Process ID to evaluate
     * @return ProcessAccessInfo Detailed access evaluation with guidance
     */
    ProcessAccessInfo evaluateProcessAccess(pid_t pid);
    
    /**
     * @brief Determine if a process is a system process
     * @param pid Process ID to check
     * @return true if process is protected as a system process
     */
    bool isSystemProcess(pid_t pid);
    
    /**
     * @brief Check if a process is protected by System Integrity Protection
     * @param pid Process ID to check
     * @return true if process is SIP-protected
     */
    bool isSIPProtected(pid_t pid);
    
    /**
     * @brief Get comprehensive guidance for entitlement configuration
     * @return std::string Detailed guidance for setting up entitlements
     */
    std::string getEntitlementsGuidance();
    
private:
    /**
     * @brief Check current System Integrity Protection status
     * @return true if SIP is enabled on the system
     */
    bool checkSIPStatus();

    /**
     * @brief Validate current application's code signing status
     * @return true if application is properly code signed
     */
    bool validateCodeSigning();

    /** System process PID threshold. */
    static constexpr pid_t SYSTEM_PROCESS_PID_THRESHOLD = 100;
};

} // namespace cheatengine
