#pragma once

#include <mach/mach.h>
#include <string>

namespace cheatengine {

class SecurityManager {
public:
    enum class AccessLevel { FULL_ACCESS, LIMITED_ACCESS, NO_ACCESS };

    struct ProcessAccessInfo {
        AccessLevel level;
        std::string restriction_reason;
    };

    ProcessAccessInfo evaluateProcessAccess(pid_t pid);
    bool isSystemProcess(pid_t pid);
    bool isSIPProtected(pid_t pid);

private:
    bool checkSIPStatus();
    bool validateCodeSigning();
    static const pid_t SYSTEM_PROCESS_PID_THRESHOLD = 100;
};

} // namespace cheatengine
