#include "cheatengine/core/application.hpp"
#include "cheatengine/core/errors.hpp"

#include <fstream>
#include <iostream>
#include <sstream>

namespace cheatengine {

Application::Application()
{
    // Initialize with default configuration
    config_ = ApplicationConfig{};
}

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
    
    try {
        // Initialize components in dependency order
        clearError();
        
        // Security manager doesn't need initialization
        // Process manager doesn't need initialization
        // Memory scanner doesn't need initialization
        // Value monitor doesn't need initialization
        // Memory writer doesn't need initialization
        
        initialized_ = true;
        return true;
        
    } catch (const std::exception& e) {
        setError("Failed to initialize application: " + std::string(e.what()));
        return false;
    }
}

void Application::shutdown()
{
    if (!initialized_) {
        return;
    }
    
    try {
        // Clean shutdown in reverse dependency order

        // Detach from any attached process
        if (process_manager_.currentProcess()) {
            detachWithCleanup();
        }

        // Clear any monitored addresses
        value_monitor_.clear();

        initialized_ = false;
        clearError();
        
    } catch (const std::exception& e) {
        // Log error but don't throw during shutdown
        std::cerr << "Warning: Error during shutdown: " << e.what() << std::endl;
    }
}

void Application::loadConfig(const std::string& config_file)
{
    // For now, use default configuration
    // In a full implementation, this would load from a file
    config_ = ApplicationConfig{};
    
    if (!config_file.empty()) {
        // TODO: Implement file-based configuration loading
        std::cout << "Note: Configuration file loading not yet implemented. Using defaults.\n";
    }
}

void Application::saveConfig(const std::string& config_file) const
{
    if (!config_file.empty()) {
        // TODO: Implement file-based configuration saving
        std::cout << "Note: Configuration file saving not yet implemented.\n";
    }
}

bool Application::attachToProcessWithValidation(pid_t pid)
{
    if (!initialized_) {
        setError("Application not initialized");
        return false;
    }
    
    clearError();
    
    try {
        // Step 1: Validate security access
        auto access_info = security_manager_.evaluateProcessAccess(pid);
        
        if (access_info.level == SecurityManager::AccessLevel::NO_ACCESS) {
            std::ostringstream oss;
            oss << "Cannot access process " << pid << ": " << access_info.restriction_reason;
            setError(oss.str());
            return false;
        }
        
        // Step 2: Attempt attachment
        if (!process_manager_.attach(pid)) {
            std::ostringstream oss;
            oss << "Failed to attach to process " << pid;
            const auto& pm_error = process_manager_.lastError();
            if (!pm_error.empty()) {
                oss << ": " << pm_error;
            }
            setError(oss.str());
            return false;
        }
        
        // Step 3: Validate attachment was successful
        const auto current_process = process_manager_.currentProcess();
        if (!current_process) {
            setError("Attachment succeeded but no current process available");
            return false;
        }
        
        // Step 4: Log successful attachment with security context
        if (config_.verbose_errors) {
            std::cout << "Successfully attached to PID " << pid;
            if (access_info.level == SecurityManager::AccessLevel::LIMITED_ACCESS) {
                std::cout << " (limited access mode)";
            }
            std::cout << std::endl;
        }
        
        return true;
        
    } catch (const CheatEngineException& e) {
        std::ostringstream oss;
        oss << "CheatEngine error during attachment: " << e.what();
        setError(oss.str());
        return false;
    } catch (const std::exception& e) {
        std::ostringstream oss;
        oss << "Unexpected error during attachment: " << e.what();
        setError(oss.str());
        return false;
    }
}

void Application::detachWithCleanup()
{
    if (!initialized_) {
        return;
    }

    try {
        // Clear any monitored addresses before detaching
        value_monitor_.clear();

        // Detach from process
        process_manager_.detach();
        
        if (config_.verbose_errors) {
            std::cout << "Detached from process and cleaned up resources." << std::endl;
        }
        
    } catch (const std::exception& e) {
        if (config_.verbose_errors) {
            std::cerr << "Warning: Error during detach cleanup: " << e.what() << std::endl;
        }
    }
}

bool Application::performSecureMemoryWrite(mach_vm_address_t address, const std::vector<uint8_t>& data)
{
    if (!initialized_) {
        setError("Application not initialized");
        return false;
    }
    
    const auto current_process = process_manager_.currentProcess();
    if (!current_process) {
        setError("No process attached");
        return false;
    }
    
    clearError();
    
    try {
        // Step 1: Check if memory writing is enabled
        if (!config_.enable_memory_writing) {
            setError("Memory writing is disabled in configuration");
            return false;
        }
        
        // Step 2: Validate write permissions
        if (!memory_writer_.canWrite(current_process->task_port, address, data.size())) {
            setError("Cannot write to address: insufficient permissions or invalid address");
            return false;
        }
        
        // Step 3: Perform the write
        if (!memory_writer_.write(current_process->task_port, address, data)) {
            setError("Memory write operation failed");
            return false;
        }
        
        if (config_.verbose_errors) {
            std::cout << "Successfully wrote " << data.size() << " bytes to 0x" 
                      << std::hex << address << std::dec << std::endl;
        }
        
        return true;
        
    } catch (const CheatEngineException& e) {
        std::ostringstream oss;
        oss << "CheatEngine error during memory write: " << e.what();
        setError(oss.str());
        return false;
    } catch (const std::exception& e) {
        std::ostringstream oss;
        oss << "Unexpected error during memory write: " << e.what();
        setError(oss.str());
        return false;
    }
}

} // namespace cheatengine