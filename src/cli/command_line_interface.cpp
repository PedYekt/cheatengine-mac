#include "cheatengine/cli/command_line_interface.hpp"
#include "cheatengine/memory/memory_region.hpp"
#include "cheatengine/memory/value_types.hpp"
#include "cheatengine/process/security_manager.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <vector>

#include <unistd.h>
#include <libproc.h>

namespace cheatengine {
namespace cli {

namespace {

constexpr std::size_t kDefaultContextBytes = 16;
constexpr std::size_t kMaxSearchResultsToDisplay = 20;

std::string bytesToHex(const std::vector<std::uint8_t>& bytes, std::size_t max_count)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    const std::size_t display_count = std::min(bytes.size(), max_count);
    for (std::size_t i = 0; i < display_count; ++i) {
        oss << std::setw(2) << static_cast<int>(bytes[i]) << ' ';
    }
    if (bytes.size() > max_count) {
        oss << "...";
    }
    return oss.str();
}

std::optional<SearchValue> parseSearchValue(const std::string& type_token, const std::string& value_token)
{
    try {
        if (type_token == "int32") {
            return SearchValue::fromInt32(static_cast<std::int32_t>(std::stol(value_token, nullptr, 0)));
        }
        if (type_token == "int64") {
            return SearchValue::fromInt64(static_cast<std::int64_t>(std::stoll(value_token, nullptr, 0)));
        }
        if (type_token == "float") {
            return SearchValue::fromFloat32(std::stof(value_token));
        }
        if (type_token == "double") {
            return SearchValue::fromFloat64(std::stod(value_token));
        }
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return std::nullopt;
}

std::string getProcessName(pid_t pid)
{
    char path_buffer[PROC_PIDPATHINFO_MAXSIZE];
    int ret = proc_pidpath(pid, path_buffer, sizeof(path_buffer));
    if (ret <= 0) {
        return "Unknown";
    }
    
    std::string full_path(path_buffer);
    size_t last_slash = full_path.find_last_of('/');
    if (last_slash != std::string::npos) {
        return full_path.substr(last_slash + 1);
    }
    return full_path;
}

void printSecurityStatus(const SecurityManager::ProcessAccessInfo& access_info)
{
    std::cout << "Security Status: ";
    switch (access_info.level) {
        case SecurityManager::AccessLevel::FULL_ACCESS:
            std::cout << "Full Access (can read/write memory)\n";
            break;
        case SecurityManager::AccessLevel::LIMITED_ACCESS:
            std::cout << "Limited Access (basic info only)\n";
            break;
        case SecurityManager::AccessLevel::NO_ACCESS:
            std::cout << "No Access\n";
            break;
    }
    
    if (!access_info.restriction_reason.empty()) {
        std::cout << "Restriction: " << access_info.restriction_reason << "\n";
    }
    
    if (!access_info.suggested_solutions.empty()) {
        std::cout << "Suggested solutions:\n";
        for (const auto& solution : access_info.suggested_solutions) {
            std::cout << "  - " << solution << "\n";
        }
    }
}

void printRegion(const MemoryRegion& region)
{
    std::ios_base::fmtflags original_flags = std::cout.flags();
    
    // Basic region info
    std::cout << "  ["
              << "0x" << std::hex << std::setw(12) << std::setfill('0') << region.start_address
              << " - 0x" << std::setw(12) << (region.start_address + region.size)
              << std::dec << std::setfill(' ') << "] ";
    
    // Size with human-readable format
    if (region.size >= 1024 * 1024) {
        std::cout << std::setw(8) << (region.size / (1024 * 1024)) << " MB  ";
    } else if (region.size >= 1024) {
        std::cout << std::setw(8) << (region.size / 1024) << " KB  ";
    } else {
        std::cout << std::setw(8) << region.size << " B   ";
    }
    
    // Protection flags with color coding (simplified)
    std::string flags_str = region.flags().toString();
    std::cout << std::setw(8) << flags_str << "  ";
    
    // Region type label
    std::cout << std::setw(15) << region.category;
    
    if (region.is_shared) {
        std::cout << " (shared)";
    }
    
    std::cout << '\n';
    std::cout.flags(original_flags);
}

} // namespace

CommandLineInterface::CommandLineInterface(Application& app)
    : app_(app)
{
}

void CommandLineInterface::run()
{
    std::cout << "=== CheatEngine - Memory Analysis Tool ===\n";
    std::cout << "A tool for macOS memory analysis and process inspection.\n";
    std::cout << "Type 'help' for commands or 'troubleshoot' for security guidance.\n";
    
    // Show configuration status
    const auto& config = app_.config();
    std::cout << "\nConfiguration:\n";
    std::cout << "• Memory writing: " << (config.enable_memory_writing ? "enabled" : "disabled") << "\n";
    std::cout << "• Max search results: " << config.max_search_results << "\n";
    std::cout << "• Monitor interval: " << config.monitor_interval.count() << "ms\n\n";

    std::string line;
    while (true) {
        std::cout << "cheatengine> " << std::flush;
        if (!std::getline(std::cin, line)) {
            break;
        }

        std::istringstream iss(line);
        std::string command;
        if (!(iss >> command)) {
            continue;
        }

        try {
            if (command == "help") {
                printHelp();
            } else if (command == "attach") {
                std::string target;
                if (!(iss >> target)) {
                    std::cout << "Usage: attach <pid|self>\n";
                    std::cout << "Example: attach 1234\n";
                    std::cout << "Example: attach self\n";
                    continue;
                }
                handleAttach(target);
            } else if (command == "detach") {
                handleDetach();
            } else if (command == "status") {
                handleStatus();
            } else if (command == "processes") {
                handleProcesses();
            } else if (command == "security") {
                std::string pid_str;
                if (!(iss >> pid_str)) {
                    std::cout << "Usage: security <pid>\n";
                    continue;
                }
                handleSecurity(pid_str);
            } else if (command == "regions") {
                handleRegions();
            } else if (command == "search") {
                std::string type_token;
                std::string value_token;
                if (!(iss >> type_token >> value_token)) {
                    std::cout << "Usage: search <type> <value>\n";
                    std::cout << "Types: int32, int64, float, double\n";
                    std::cout << "Example: search int32 42\n";
                    continue;
                }
                handleSearch(type_token, value_token, true); // Fast search by default
            } else if (command == "search-all") {
                std::string type_token;
                std::string value_token;
                if (!(iss >> type_token >> value_token)) {
                    std::cout << "Usage: search-all <type> <value>\n";
                    std::cout << "Types: int32, int64, float, double\n";
                    std::cout << "Example: search-all int32 42\n";
                    continue;
                }
                handleSearch(type_token, value_token, false); // Complete search
            } else if (command == "write") {
                std::string address_str, type_str, value_str;
                if (!(iss >> address_str >> type_str >> value_str)) {
                    std::cout << "Usage: write <address> <type> <value>\n";
                    std::cout << "Example: write 0x7fff5fbff000 int32 42\n";
                    continue;
                }
                handleWrite(address_str, type_str, value_str);
            } else if (command == "monitor") {
                std::string subcommand;
                if (!(iss >> subcommand)) {
                    std::cout << "Usage: monitor <add|list|poll|clear>\n";
                    continue;
                }
                if (subcommand == "add") {
                    std::string address_token;
                    std::string size_token;
                    if (!(iss >> address_token >> size_token)) {
                        std::cout << "Usage: monitor add <address> <size>\n";
                        std::cout << "Example: monitor add 0x7fff5fbff000 4\n";
                        continue;
                    }
                    handleMonitorAdd(address_token, size_token);
                } else if (subcommand == "list") {
                    handleMonitorList();
                } else if (subcommand == "poll") {
                    handleMonitorPoll();
                } else if (subcommand == "clear") {
                    handleMonitorClear();
                } else {
                    std::cout << "Unknown monitor command. Use: add, list, poll, clear\n";
                }
            } else if (command == "troubleshoot") {
                handleTroubleshoot();
            } else if (command == "entitlements") {
                handleEntitlements();
            } else if (command == "sip-status") {
                handleSIPStatus();
            } else if (command == "config") {
                std::string subcommand;
                if (!(iss >> subcommand)) {
                    std::cout << "Usage: config <show|set|reset>\n";
                    continue;
                }
                if (subcommand == "show") {
                    handleConfigShow();
                } else if (subcommand == "set") {
                    std::string key, value;
                    if (!(iss >> key >> value)) {
                        std::cout << "Usage: config set <key> <value>\n";
                        continue;
                    }
                    handleConfigSet(key, value);
                } else if (subcommand == "reset") {
                    handleConfigReset();
                } else {
                    std::cout << "Unknown config command. Use: show, set, reset\n";
                }
            } else if (command == "quit" || command == "exit") {
                std::cout << "Shutting down CheatEngine...\n";
                app_.shutdown();
                std::cout << "Goodbye.\n";
                break;
            } else if (command.empty()) {
                continue;
            } else {
                std::cout << "Unknown command: '" << command << "'\n";
                std::cout << "Type 'help' for a list of available commands.\n";
            }
        } catch (const std::exception& e) {
            std::cout << "Error: " << e.what() << "\n";
            std::cout << "Use 'troubleshoot' for help with common issues.\n";
        }
        
        std::cout << "\n"; // Add spacing between commands
    }
}

void CommandLineInterface::printHelp() const
{
    std::cout << "CheatEngine - Memory Analysis Tool\n\n"
                 "Process Management:\n"
                 "  attach <pid>                  Attach to a process by PID\n"
                 "  attach self                   Attach to the CheatEngine process\n"
                 "  detach                        Detach from the current process\n"
                 "  status                        Show current attachment and security info\n"
                 "  processes                     List running processes you can attach to\n"
                 "  security <pid>                Check security restrictions for a process\n"
                 "\n"
                 "Memory Analysis:\n"
                 "  regions                       List memory regions of attached process\n"
                 "  search <type> <value>         Fast search in likely regions (STACK, HEAP, DATA)\n"
                 "  search-all <type> <value>     Search all readable memory regions (slower)\n"
                 "  write <address> <type> <value> Write value to memory address\n"
                 "\n"
                 "Monitoring:\n"
                 "  monitor add <address> <size>  Add address to monitor (size in bytes)\n"
                 "  monitor list                  Show monitored addresses\n"
                 "  monitor poll                  Poll monitored addresses for changes\n"
                 "  monitor clear                 Clear all monitored addresses\n"
                 "\n"
                 "Security & Troubleshooting:\n"
                 "  troubleshoot                  Show security troubleshooting guide\n"
                 "  entitlements                  Show entitlements guidance\n"
                 "  sip-status                    Check System Integrity Protection status\n"
                 "\n"
                 "Configuration:\n"
                 "  config show                   Show current configuration\n"
                 "  config set <key> <value>      Set configuration option\n"
                 "  config reset                  Reset to default configuration\n"
                 "\n"
                 "General:\n"
                 "  help                          Show this help message\n"
                 "  quit                          Exit the program\n"
                 "\n"
                 "Note: This tool uses Mach kernel APIs and only works with processes you own.\n";
}

void CommandLineInterface::handleAttach(const std::string& target)
{
    pid_t pid = 0;
    if (target == "self") {
        pid = getpid();
    } else {
        try {
            pid = static_cast<pid_t>(std::stol(target, nullptr, 0));
        } catch (const std::exception&) {
            std::cout << "Invalid PID.\n";
            return;
        }
    }

    std::cout << "Attempting to attach to process: " << getProcessName(pid) << " (PID " << pid << ")\n";
    
    // Check security status before attempting attachment
    auto access_info = app_.securityManager().evaluateProcessAccess(pid);
    printSecurityStatus(access_info);
    
    if (access_info.level == SecurityManager::AccessLevel::NO_ACCESS) {
        std::cout << "Cannot attach to this process due to security restrictions.\n";
        std::cout << "Use 'troubleshoot' command for help.\n";
        return;
    }

    // Use the integrated attachment method
    if (app_.attachToProcessWithValidation(pid)) {
        const auto info = app_.processManager().currentProcess();
        std::cout << "Successfully attached to PID " << pid;
        if (info && !info->executable_path.empty()) {
            std::cout << " (" << info->executable_path << ")";
        }
        std::cout << '\n';
        
        if (access_info.level == SecurityManager::AccessLevel::LIMITED_ACCESS) {
            std::cout << "Note: Limited access mode - some features may be restricted.\n";
        }
        
    } else {
        std::cout << "Failed to attach to PID " << pid << ".\n";
        const auto& error = app_.getLastError();
        if (!error.empty()) {
            std::cout << "  Details: " << error << '\n';
        }
        std::cout << "Use 'security " << pid << "' for detailed security analysis.\n";
    }
}

void CommandLineInterface::handleDetach()
{
    app_.detachWithCleanup();
    std::cout << "Detached from process and cleaned up resources.\n";
}

void CommandLineInterface::handleStatus() const
{
    if (const auto info = app_.processManager().currentProcess()) {
        std::cout << "=== Current Process Status ===\n";
        std::cout << "PID: " << info->pid << "\n";
        std::cout << "Process Name: " << getProcessName(info->pid) << "\n";
        if (!info->executable_path.empty()) {
            std::cout << "Executable Path: " << info->executable_path << "\n";
        }
        std::cout << "Task Port: " << (info->task_port != MACH_PORT_NULL ? "Valid" : "Invalid") << "\n";
        
        // Show security context
        SecurityManager security_manager;
        auto access_info = security_manager.evaluateProcessAccess(info->pid);
        std::cout << "\n=== Security Context ===\n";
        printSecurityStatus(access_info);
        
        // Show monitoring status
        const auto monitored = app_.valueMonitor().tracked();
        std::cout << "\n=== Monitoring Status ===\n";
        std::cout << "Monitored Addresses: " << monitored.size() << "\n";
        
    } else {
        std::cout << "No process attached.\n";
        std::cout << "Use 'attach <pid>' or 'attach self' to attach to a process.\n";
        std::cout << "Use 'processes' to see available processes.\n";
    }
}

void CommandLineInterface::handleProcesses() const
{
    std::cout << "=== Available Processes (User-owned only) ===\n";
    std::cout << "Note: Only showing processes you can potentially attach to.\n\n";
    
    // Get list of all processes
    int num_pids = proc_listallpids(nullptr, 0);
    if (num_pids <= 0) {
        std::cout << "Failed to get process list.\n";
        return;
    }
    
    std::vector<pid_t> pids(num_pids);
    num_pids = proc_listallpids(pids.data(), num_pids * sizeof(pid_t));
    if (num_pids <= 0) {
        std::cout << "Failed to get process list.\n";
        return;
    }
    
    SecurityManager security_manager;
    uid_t current_uid = getuid();
    
    std::cout << std::left << std::setw(8) << "PID" 
              << std::setw(25) << "Process Name" 
              << std::setw(15) << "Access Level" 
              << "Notes\n";
    std::cout << std::string(70, '-') << "\n";
    
    int shown_count = 0;
    for (int i = 0; i < num_pids && shown_count < 50; ++i) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;
        
        // Check if we own this process
        struct proc_bsdinfo proc_info;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &proc_info, sizeof(proc_info)) <= 0) {
            continue;
        }
        
        if (proc_info.pbi_uid != current_uid) {
            continue; // Skip processes we don't own
        }
        
        auto access_info = security_manager.evaluateProcessAccess(pid);
        if (access_info.level == SecurityManager::AccessLevel::NO_ACCESS) {
            continue; // Skip inaccessible processes
        }
        
        std::string process_name = getProcessName(pid);
        std::string access_level;
        std::string notes;
        
        switch (access_info.level) {
            case SecurityManager::AccessLevel::FULL_ACCESS:
                access_level = "Full";
                break;
            case SecurityManager::AccessLevel::LIMITED_ACCESS:
                access_level = "Limited";
                notes = "Basic info only";
                break;
            default:
                continue;
        }
        
        std::cout << std::left << std::setw(8) << pid
                  << std::setw(25) << process_name.substr(0, 24)
                  << std::setw(15) << access_level
                  << notes << "\n";
        shown_count++;
    }
    
    if (shown_count == 0) {
        std::cout << "No accessible processes found.\n";
        std::cout << "Try running some applications first, or use 'attach self'.\n";
    } else {
        std::cout << "\nShowing " << shown_count << " accessible processes.\n";
        std::cout << "Use 'attach <pid>' to attach to a process.\n";
    }
}

void CommandLineInterface::handleSecurity(const std::string& pid_str) const
{
    pid_t pid = 0;
    try {
        pid = static_cast<pid_t>(std::stol(pid_str, nullptr, 0));
    } catch (const std::exception&) {
        std::cout << "Invalid PID.\n";
        return;
    }
    
    SecurityManager security_manager;
    
    std::cout << "=== Security Analysis for PID " << pid << " ===\n";
    std::cout << "Process: " << getProcessName(pid) << "\n\n";
    
    // Check if it's a system process
    if (security_manager.isSystemProcess(pid)) {
        std::cout << "System Process: Yes (protected by macOS)\n";
    } else {
        std::cout << "System Process: No\n";
    }
    
    // Check SIP protection
    if (security_manager.isSIPProtected(pid)) {
        std::cout << "SIP Protected: Yes (System Integrity Protection active)\n";
    } else {
        std::cout << "SIP Protected: No\n";
    }
    
    // Get detailed access info
    auto access_info = security_manager.evaluateProcessAccess(pid);
    std::cout << "\n";
    printSecurityStatus(access_info);
}

void CommandLineInterface::handleRegions() const
{
    const auto info = app_.processManager().currentProcess();
    if (!info) {
        std::cout << "No process attached.\n";
        return;
    }

    const auto regions = app_.memoryScanner().enumerate(info->task_port);
    
    std::cout << "=== Memory Regions for PID " << info->pid << " ===\n";
    std::cout << "Process: " << getProcessName(info->pid) << "\n";
    std::cout << "Total regions: " << regions.size() << "\n\n";
    
    std::cout << "Format: [Start - End] Size Protection Type\n\n";
    
    // Group regions by type for better understanding
    std::map<std::string, std::vector<MemoryRegion>> regions_by_type;
    size_t total_size = 0;
    
    for (const auto& region : regions) {
        regions_by_type[region.category].push_back(region);
        total_size += region.size;
    }
    
    // Display regions grouped by type
    for (const auto& [type, type_regions] : regions_by_type) {
        std::cout << "--- " << type << " regions (" << type_regions.size() << ") ---\n";
        for (const auto& region : type_regions) {
            printRegion(region);
        }
        std::cout << "\n";
    }
    
    // Summary statistics
    std::cout << "=== Memory Usage Summary ===\n";
    std::cout << "Total virtual memory: ";
    if (total_size >= 1024 * 1024 * 1024) {
        std::cout << (total_size / (1024 * 1024 * 1024)) << " GB\n";
    } else if (total_size >= 1024 * 1024) {
        std::cout << (total_size / (1024 * 1024)) << " MB\n";
    } else {
        std::cout << (total_size / 1024) << " KB\n";
    }
    
    std::cout << "Region types: " << regions_by_type.size() << "\n";
    
}

void CommandLineInterface::handleSearch(const std::string& type_token, const std::string& value_token, bool fast_search)
{
    const auto info = app_.processManager().currentProcess();
    if (!info) {
        std::cout << "No process attached.\n";
        return;
    }

    const auto value = parseSearchValue(type_token, value_token);
    if (!value) {
        std::cout << "Unsupported type or invalid value. Supported types: int32, int64, float, double\n";
        return;
    }

    std::cout << "=== Memory Search ===\n";
    std::cout << "Searching for " << type_token << " value: " << value_token << "\n";
    std::cout << "Target process: " << getProcessName(info->pid) << " (PID " << info->pid << ")\n";
    std::cout << "Search mode: " << (fast_search ? "Fast (STACK, HEAP, DATA only)" : "Complete (all regions)") << "\n";
    
    const auto results = fast_search ? 
        app_.memoryScanner().searchFast(info->task_port, *value) :
        app_.memoryScanner().search(info->task_port, *value);
        
    if (results.empty()) {
        std::cout << "No matches found.\n";
        if (fast_search) {
            std::cout << "Try 'search-all " << type_token << " " << value_token << "' for a complete search.\n";
        }
        return;
    }

    std::cout << "\nFound " << results.size() << " matches";
    if (results.size() > kMaxSearchResultsToDisplay) {
        std::cout << " (showing first " << kMaxSearchResultsToDisplay << ")";
    }
    std::cout << ":\n\n";

    const std::size_t display_count = std::min<std::size_t>(results.size(), kMaxSearchResultsToDisplay);
    
    // Get memory regions for context
    const auto regions = app_.memoryScanner().enumerate(info->task_port);
    
    for (std::size_t i = 0; i < display_count; ++i) {
        const auto& result = results[i];
        
        // Find which region this address belongs to
        std::string region_info = "Unknown region";
        for (const auto& region : regions) {
            if (result.address >= region.start_address && 
                result.address < region.start_address + region.size) {
                region_info = region.category + " (" + region.flags().toString() + ")";
                break;
            }
        }
        
        std::cout << "  [" << (i + 1) << "] Address: 0x" << std::hex << result.address << std::dec << "\n";
        std::cout << "      Region: " << region_info << "\n";
        std::cout << "      Context: " << bytesToHex(result.context, kDefaultContextBytes) << "\n";
        
        std::cout << "\n";
    }
    
    if (results.size() > display_count) {
        std::cout << "  ... " << (results.size() - display_count) << " more results not shown.\n\n";
    }
    
}

void CommandLineInterface::handleWrite(const std::string& address_str, const std::string& type_str, const std::string& value_str)
{
    const auto info = app_.processManager().currentProcess();
    if (!info) {
        std::cout << "No process attached.\n";
        return;
    }
    
    mach_vm_address_t address = 0;
    try {
        address = static_cast<mach_vm_address_t>(std::stoull(address_str, nullptr, 0));
    } catch (const std::exception&) {
        std::cout << "Invalid address.\n";
        return;
    }
    
    auto search_value = parseSearchValue(type_str, value_str);
    if (!search_value) {
        std::cout << "Invalid type or value. Supported types: int32, int64, float, double\n";
        return;
    }
    
    const auto& data = search_value->data();
    
    // Show confirmation if required
    if (app_.config().require_confirmation_for_writes) {
        std::cout << "About to write " << data.size() << " bytes to address 0x" 
                  << std::hex << address << std::dec << "\n";
        std::cout << "Data: " << bytesToHex(data, data.size()) << "\n";
        std::cout << "This operation may modify program behavior. Continue? (y/N): ";
        
        std::string response;
        std::getline(std::cin, response);
        if (response != "y" && response != "Y" && response != "yes") {
            std::cout << "Write operation cancelled.\n";
            return;
        }
    }
    
    // Use the integrated secure write method
    if (!app_.performSecureMemoryWrite(address, data)) {
        std::cout << "Failed to write to address 0x" << std::hex << address << std::dec << "\n";
        const auto& error = app_.getLastError();
        if (!error.empty()) {
            std::cout << "Error: " << error << "\n";
        }
        std::cout << "\nThis may be due to:\n";
        std::cout << "- Invalid memory address\n";
        std::cout << "- Write-protected memory region\n";
        std::cout << "- Insufficient permissions\n";
        std::cout << "- Memory writing disabled in configuration\n";
        std::cout << "Use 'regions' command to check memory protection flags.\n";
    }
}

void CommandLineInterface::handleMonitorAdd(const std::string& address_token, const std::string& size_token)
{
    const auto info = app_.processManager().currentProcess();
    if (!info) {
        std::cout << "No process attached.\n";
        return;
    }

    mach_vm_address_t address = 0;
    std::size_t size = 0;
    try {
        address = static_cast<mach_vm_address_t>(std::stoull(address_token, nullptr, 0));
        size = static_cast<std::size_t>(std::stoul(size_token, nullptr, 0));
    } catch (const std::exception&) {
        std::cout << "Invalid address or size.\n";
        return;
    }

    if (size == 0) {
        std::cout << "Size must be greater than zero.\n";
        return;
    }

    if (app_.valueMonitor().addAddress(address, size)) {
        std::cout << "Added address 0x" << std::hex << address << std::dec
                  << " (" << size << " bytes) to monitor list.\n";
    } else {
        std::cout << "Failed to add address: maximum number of monitored addresses reached.\n";
        std::cout << "Use 'monitor clear' to remove existing addresses.\n";
    }
}

void CommandLineInterface::handleMonitorList() const
{
    const auto list = app_.valueMonitor().tracked();
    if (list.empty()) {
        std::cout << "No addresses being monitored.\n";
        return;
    }

    std::cout << "=== Monitored Memory Addresses ===\n";
    std::cout << "Total addresses: " << list.size() << "\n\n";
    
    // Get current process info for region context
    const auto info = app_.processManager().currentProcess();
    std::vector<MemoryRegion> regions;
    if (info) {
        regions = app_.memoryScanner().enumerate(info->task_port);
    }

    for (size_t i = 0; i < list.size(); ++i) {
        const auto& entry = list[i];
        
        std::cout << "  [" << (i + 1) << "] Address: 0x" << std::hex << entry.address << std::dec << "\n";
        std::cout << "      Size: " << entry.value_size << " bytes\n";
        
        // Find region context
        if (info) {
            for (const auto& region : regions) {
                if (entry.address >= region.start_address && 
                    entry.address < region.start_address + region.size) {
                    std::cout << "      Region: " << region.category 
                              << " (" << region.flags().toString() << ")\n";
                    break;
                }
            }
        }
        
        std::cout << "\n";
    }
}

void CommandLineInterface::handleMonitorPoll()
{
    const auto info = app_.processManager().currentProcess();
    if (!info) {
        std::cout << "No process attached.\n";
        return;
    }

    auto changes = app_.valueMonitor().poll(info->task_port);
    if (changes.empty()) {
        std::cout << "No changes detected.\n";
        return;
    }

    std::cout << "Detected " << changes.size() << " changes:\n";
    for (const auto& change : changes) {
        std::cout << "  0x" << std::hex << change.address << std::dec
                  << " old: " << bytesToHex(change.old_value, kDefaultContextBytes)
                  << " new: " << bytesToHex(change.new_value, kDefaultContextBytes)
                  << '\n';
    }
}

void CommandLineInterface::handleMonitorClear()
{
    app_.valueMonitor().clear();
    std::cout << "Cleared all monitored addresses.\n";
}

void CommandLineInterface::handleTroubleshoot() const
{
    std::cout << "\n=== CheatEngine Security Troubleshooting Guide ===\n\n"
                 "Common Issues and Solutions:\n\n"
                 "1. 'Permission denied' or 'Operation not permitted':\n"
                 "   - Ensure you're targeting a process you own\n"
                 "   - Check that CheatEngine is properly code signed\n"
                 "   - Verify entitlements are correctly configured\n\n"
                 "2. 'Missing entitlements' error:\n"
                 "   - Run: codesign -d --entitlements - /path/to/cheatengine\n"
                 "   - Ensure com.apple.security.get-task-allow is present\n"
                 "   - Re-sign with proper entitlements if needed\n\n"
                 "3. System processes are protected:\n"
                 "   - System Integrity Protection (SIP) blocks access\n"
                 "   - Only attach to your own user processes\n"
                 "   - Use 'processes' command to see available targets\n\n"
                 "4. Code signing issues:\n"
                 "   - Sign with: codesign --force --sign \"Apple Development\" \\\n"
                 "     --entitlements debug-entitlements.plist cheatengine\n"
                 "   - Ensure you have a valid Apple Developer certificate\n\n";
}

void CommandLineInterface::handleEntitlements() const
{
    SecurityManager security_manager;
    std::cout << security_manager.getEntitlementsGuidance() << "\n";
}

void CommandLineInterface::handleSIPStatus() const
{
    SecurityManager security_manager;
    
    std::cout << "=== System Integrity Protection Status ===\n";
    
    // This is a simplified check - in a real implementation, you'd check SIP status
    std::cout << "SIP is a macOS security feature that protects system processes.\n";
    std::cout << "CheatEngine can only attach to processes you own.\n";
    std::cout << "System processes and processes owned by other users are protected.\n\n";
    
    std::cout << "To check full SIP status, run in Terminal:\n";
    std::cout << "  csrutil status\n\n";
}

void CommandLineInterface::handleConfigShow() const
{
    const auto& config = app_.config();
    
    std::cout << "=== Current Configuration ===\n\n";
    
    std::cout << "Search Settings:\n";
    std::cout << "  max_search_results: " << config.max_search_results << "\n";
    std::cout << "  search_chunk_size: " << config.search_chunk_size << " bytes\n\n";
    
    std::cout << "Monitoring Settings:\n";
    std::cout << "  monitor_interval: " << config.monitor_interval.count() << " ms\n";
    std::cout << "  max_monitored_addresses: " << config.max_monitored_addresses << "\n\n";
    
    std::cout << "Display Settings:\n";
    std::cout << "  verbose_errors: " << (config.verbose_errors ? "true" : "false") << "\n";
    std::cout << "  context_bytes: " << config.context_bytes << "\n\n";
    
    std::cout << "Security Settings:\n";
    std::cout << "  enable_memory_writing: " << (config.enable_memory_writing ? "true" : "false") << "\n";
    std::cout << "  require_confirmation_for_writes: " << (config.require_confirmation_for_writes ? "true" : "false") << "\n\n";
    
    std::cout << "Performance Settings:\n";
    std::cout << "  memory_read_timeout_ms: " << config.memory_read_timeout_ms << " ms\n";
    std::cout << "  use_chunked_reading: " << (config.use_chunked_reading ? "true" : "false") << "\n\n";
}

void CommandLineInterface::handleConfigSet(const std::string& key, const std::string& value)
{
    auto& config = app_.config();
    
    try {
        if (key == "max_search_results") {
            config.max_search_results = std::stoul(value);
        } else if (key == "search_chunk_size") {
            config.search_chunk_size = std::stoul(value);
        } else if (key == "monitor_interval") {
            config.monitor_interval = std::chrono::milliseconds(std::stoul(value));
        } else if (key == "max_monitored_addresses") {
            config.max_monitored_addresses = std::stoul(value);
        } else if (key == "verbose_errors") {
            config.verbose_errors = (value == "true" || value == "1" || value == "yes");
        } else if (key == "context_bytes") {
            config.context_bytes = std::stoul(value);
        } else if (key == "enable_memory_writing") {
            config.enable_memory_writing = (value == "true" || value == "1" || value == "yes");
        } else if (key == "require_confirmation_for_writes") {
            config.require_confirmation_for_writes = (value == "true" || value == "1" || value == "yes");
        } else if (key == "memory_read_timeout_ms") {
            config.memory_read_timeout_ms = std::stoul(value);
        } else if (key == "use_chunked_reading") {
            config.use_chunked_reading = (value == "true" || value == "1" || value == "yes");
        } else {
            std::cout << "Unknown configuration key: " << key << "\n";
            std::cout << "Use 'config show' to see available options.\n";
            return;
        }
        
        std::cout << "Configuration updated: " << key << " = " << value << "\n";
        
        // Save configuration after update
        // Note: We'll use a default path for now
        app_.saveConfig("cheatengine.conf");
        
    } catch (const std::exception& e) {
        std::cout << "Invalid value for " << key << ": " << e.what() << "\n";
    }
}

void CommandLineInterface::handleConfigReset()
{
    app_.config() = ApplicationConfig{};
    std::cout << "Configuration reset to defaults.\n";
    // Save the reset configuration
    app_.saveConfig("cheatengine.conf");
}

} // namespace cli
} // namespace cheatengine
