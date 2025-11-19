#include "cheatengine/core/application.hpp"
#include "cheatengine/core/errors.hpp"

#include <fstream>
#include <fstream>
#include <sstream>
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
    // Start with defaults
    config_ = ApplicationConfig{};
    
    if (config_file.empty()) {
        return;
    }
    
    std::ifstream file(config_file);
    if (!file.is_open()) {
        // It's okay if the config file doesn't exist yet, we'll just use defaults
        return;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        std::istringstream iss(line);
        std::string key;
        if (std::getline(iss, key, '=')) {
            std::string value;
            if (std::getline(iss, value)) {
                // Trim whitespace
                // (Simple trim implementation)
                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);
                
                try {
                    if (key == "max_search_results") {
                        config_.max_search_results = std::stoul(value);
                    } else if (key == "search_chunk_size") {
                        config_.search_chunk_size = std::stoul(value);
                    } else if (key == "monitor_interval") {
                        config_.monitor_interval = std::chrono::milliseconds(std::stoul(value));
                    } else if (key == "max_monitored_addresses") {
                        config_.max_monitored_addresses = std::stoul(value);
                    } else if (key == "show_educational_info") {
                        config_.show_educational_info = (value == "true" || value == "1" || value == "yes");
                    } else if (key == "verbose_errors") {
                        config_.verbose_errors = (value == "true" || value == "1" || value == "yes");
                    } else if (key == "context_bytes") {
                        config_.context_bytes = std::stoul(value);
                    } else if (key == "enable_memory_writing") {
                        config_.enable_memory_writing = (value == "true" || value == "1" || value == "yes");
                    } else if (key == "require_confirmation_for_writes") {
                        config_.require_confirmation_for_writes = (value == "true" || value == "1" || value == "yes");
                    } else if (key == "memory_read_timeout_ms") {
                        config_.memory_read_timeout_ms = std::stoul(value);
                    } else if (key == "use_chunked_reading") {
                        config_.use_chunked_reading = (value == "true" || value == "1" || value == "yes");
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Warning: Failed to parse config option " << key << ": " << e.what() << std::endl;
                }
            }
        }
    }
}

void Application::saveConfig(const std::string& config_file)
{
    if (config_file.empty()) {
        return;
    }
    
    std::ofstream file(config_file);
    if (!file.is_open()) {
        setError("Failed to open configuration file for writing: " + config_file);
        return;
    }
    
    file << "# CheatEngine Configuration File\n";
    file << "# Generated automatically\n\n";
    
    file << "# Search Settings\n";
    file << "max_search_results=" << config_.max_search_results << "\n";
    file << "search_chunk_size=" << config_.search_chunk_size << "\n\n";
    
    file << "# Monitoring Settings\n";
    file << "monitor_interval=" << config_.monitor_interval.count() << "\n";
    file << "max_monitored_addresses=" << config_.max_monitored_addresses << "\n\n";
    
    file << "# Display Settings\n";
    file << "show_educational_info=" << (config_.show_educational_info ? "true" : "false") << "\n";
    file << "verbose_errors=" << (config_.verbose_errors ? "true" : "false") << "\n";
    file << "context_bytes=" << config_.context_bytes << "\n\n";
    
    file << "# Security Settings\n";
    file << "enable_memory_writing=" << (config_.enable_memory_writing ? "true" : "false") << "\n";
    file << "require_confirmation_for_writes=" << (config_.require_confirmation_for_writes ? "true" : "false") << "\n\n";
    
    file << "# Performance Settings\n";
    file << "memory_read_timeout_ms=" << config_.memory_read_timeout_ms << "\n";
    file << "use_chunked_reading=" << (config_.use_chunked_reading ? "true" : "false") << "\n";
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