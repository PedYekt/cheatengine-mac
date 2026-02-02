#include "cheatengine/core/application.hpp"
#include "cheatengine/core/errors.hpp"

#include <iostream>

namespace cheatengine {

Application::Application() {}

Application::~Application()
{
    if (initialized_) {
        shutdown();
    }
}

bool Application::initialize()
{
    if (initialized_) {
        return true;
    }

    initialized_ = true;
    return true;
}

void Application::shutdown()
{
    if (!initialized_) {
        return;
    }

    if (process_manager_.currentProcess()) {
        detachWithCleanup();
    }

    value_monitor_.clear();
    initialized_ = false;
}

bool Application::attachToProcessWithValidation(pid_t pid)
{
    if (!initialized_) {
        setError("Application not initialized");
        return false;
    }

    clearError();

    auto access_info = security_manager_.evaluateProcessAccess(pid);

    if (access_info.level == SecurityManager::AccessLevel::NO_ACCESS) {
        setError("Cannot access process " + std::to_string(pid) + ": " + access_info.restriction_reason);
        return false;
    }

    if (!process_manager_.attach(pid)) {
        std::string error_msg = "Failed to attach to process " + std::to_string(pid);
        if (!process_manager_.lastError().empty()) {
            error_msg += ": " + process_manager_.lastError();
        }
        setError(error_msg);
        return false;
    }

    if (!process_manager_.currentProcess()) {
        setError("Attachment failed");
        return false;
    }

    return true;
}

void Application::detachWithCleanup()
{
    if (!initialized_) {
        return;
    }

    value_monitor_.clear();
    process_manager_.detach();
}

bool Application::performSecureMemoryWrite(mach_vm_address_t address, const std::vector<uint8_t>& data)
{
    if (!initialized_) {
        setError("Application not initialized");
        return false;
    }

    auto current_process = process_manager_.currentProcess();
    if (!current_process) {
        setError("No process attached");
        return false;
    }

    clearError();

    if (!config_.enable_memory_writing) {
        setError("Memory writing is disabled");
        return false;
    }

    if (!memory_writer_.canWrite(current_process->task_port, address, data.size())) {
        setError("Cannot write to address");
        return false;
    }

    if (!memory_writer_.write(current_process->task_port, address, data)) {
        setError("Memory write failed");
        return false;
    }

    return true;
}

} // namespace cheatengine
