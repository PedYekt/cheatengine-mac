#include "cheatengine/core/application.hpp"
#include "cheatengine/memory/memory_region.hpp"
#include "cheatengine/memory/value_types.hpp"
#include "cheatengine/process/security_manager.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <unistd.h>
#include <libproc.h>

namespace {

using cheatengine::Application;
using cheatengine::ApplicationConfig;
using cheatengine::MemoryRegion;
using cheatengine::SearchValue;
using cheatengine::SecurityManager;

constexpr std::size_t kDefaultContextBytes = 16;
constexpr std::size_t kMaxSearchResultsToDisplay = 20;

void printHelp()
{
    std::cout << "CheatEngine - Educational Memory Analysis Tool\n\n"
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
                 "  regions-edu                   List regions with educational explanations\n"
                 "  search <type> <value>         Fast search in likely regions (STACK, HEAP, DATA)\n"
                 "  search-all <type> <value>     Search all readable memory regions (slower)\n"
                 "  search-edu <type> <value>     Search with educational explanations\n"
                 "  write <address> <type> <value> Write value to memory address\n"
                 "\n"
                 "Monitoring:\n"
                 "  monitor add <address> <size>  Add address to monitor (size in bytes)\n"
                 "  monitor list                  Show monitored addresses\n"
                 "  monitor list-edu              Show monitored addresses with explanations\n"
                 "  monitor poll                  Poll monitored addresses for changes\n"
                 "  monitor clear                 Clear all monitored addresses\n"
                 "\n"
                 "Educational Features:\n"
                 "  memory-concepts               Learn about virtual memory concepts\n"
                 "  mach-apis                     Learn about Mach kernel APIs\n"
                 "  security-model                Learn about macOS security model\n"
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
                 "Educational Note: This tool demonstrates macOS memory management concepts\n"
                 "using Mach kernel APIs. It only works with processes you own.\n"
                 "Commands ending with '-edu' provide detailed educational explanations.\n";
}

void printRegion(const MemoryRegion& region, bool show_educational_info = false)
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
    
    // Region type with educational context
    std::cout << std::setw(15) << region.category;
    
    if (region.is_shared) {
        std::cout << " (shared)";
    }
    
    if (show_educational_info) {
        std::cout << "\n    └─ ";
        
        // Add educational explanations based on region type
        if (region.category == "STACK") {
            std::cout << "Stack: Stores function call frames, local variables, return addresses";
        } else if (region.category == "HEAP") {
            std::cout << "Heap: Dynamic memory allocation area (malloc, new)";
        } else if (region.category == "CODE") {
            std::cout << "Code: Executable instructions, typically read-only for security";
        } else if (region.category == "DATA") {
            std::cout << "Data: Global and static variables, initialized data";
        } else if (region.category == "LIBRARY") {
            std::cout << "Library: Shared library code and data (dylib)";
        } else if (region.category == "GUARD") {
            std::cout << "Guard: Protection page to detect buffer overflows";
        } else {
            std::cout << "Virtual memory region managed by the kernel";
        }
        
        // Add protection explanation
        if (flags_str.find('r') != std::string::npos && 
            flags_str.find('w') != std::string::npos && 
            flags_str.find('x') != std::string::npos) {
            std::cout << " [RWX: Full access - rare and potentially dangerous]";
        } else if (flags_str.find('x') != std::string::npos) {
            std::cout << " [Executable: Contains CPU instructions]";
        } else if (flags_str.find('w') != std::string::npos) {
            std::cout << " [Writable: Can be modified]";
        } else if (flags_str.find('r') != std::string::npos) {
            std::cout << " [Read-only: Protected from modification]";
        }
    }
    
    std::cout << '\n';
    std::cout.flags(original_flags);
}

void printMemoryEducationalInfo()
{
    std::cout << "\n=== Memory Management Educational Information ===\n\n";
    
    std::cout << "Virtual Memory Concepts:\n";
    std::cout << "• Each process has its own virtual address space (typically 64-bit on modern macOS)\n";
    std::cout << "• Virtual addresses are mapped to physical RAM pages by the Memory Management Unit (MMU)\n";
    std::cout << "• Pages can be swapped to disk when physical memory is low\n";
    std::cout << "• Memory protection prevents unauthorized access between processes\n\n";
    
    std::cout << "Memory Region Types:\n";
    std::cout << "• STACK: Grows downward, stores function calls and local variables\n";
    std::cout << "• HEAP: Grows upward, used for dynamic allocation (malloc/free)\n";
    std::cout << "• CODE: Contains executable instructions, usually read-only\n";
    std::cout << "• DATA: Global variables and constants\n";
    std::cout << "• LIBRARY: Shared code from system libraries (dylibs)\n\n";
    
    std::cout << "Protection Flags (from mach/vm_prot.h):\n";
    std::cout << "• VM_PROT_READ (r): Memory can be read\n";
    std::cout << "• VM_PROT_WRITE (w): Memory can be written\n";
    std::cout << "• VM_PROT_EXECUTE (x): Memory contains executable code\n";
    std::cout << "• Combinations like 'r--' (read-only) or 'rw-' (read-write) are common\n\n";
    
    std::cout << "Mach VM APIs Used:\n";
    std::cout << "• mach_vm_region(): Enumerate memory regions\n";
    std::cout << "• mach_vm_read_overwrite(): Read memory contents\n";
    std::cout << "• mach_vm_write(): Write to memory (requires permissions)\n";
    std::cout << "• task_for_pid(): Get task port for process access\n\n";
    
    std::cout << "Security Implications:\n";
    std::cout << "• Process isolation prevents unauthorized memory access\n";
    std::cout << "• Code signing ensures executable integrity\n";
    std::cout << "• System Integrity Protection (SIP) protects system processes\n";
    std::cout << "• Entitlements control access to debugging APIs\n\n";
}

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

void printTroubleshootingGuide()
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
                 "   - Ensure you have a valid Apple Developer certificate\n\n"
                 "Educational Purpose:\n"
                 "This tool demonstrates macOS security mechanisms including:\n"
                 "- Process isolation and ownership validation\n"
                 "- Code signing and entitlements system\n"
                 "- System Integrity Protection (SIP)\n"
                 "- Mach kernel API security model\n\n";
}

void handleAttach(Application& app, const std::string& target)
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
    auto access_info = app.securityManager().evaluateProcessAccess(pid);
    printSecurityStatus(access_info);
    
    if (access_info.level == SecurityManager::AccessLevel::NO_ACCESS) {
        std::cout << "Cannot attach to this process due to security restrictions.\n";
        std::cout << "Use 'troubleshoot' command for help.\n";
        return;
    }

    // Use the integrated attachment method
    if (app.attachToProcessWithValidation(pid)) {
        const auto info = app.processManager().currentProcess();
        std::cout << "Successfully attached to PID " << pid;
        if (info && !info->executable_path.empty()) {
            std::cout << " (" << info->executable_path << ")";
        }
        std::cout << '\n';
        
        if (access_info.level == SecurityManager::AccessLevel::LIMITED_ACCESS) {
            std::cout << "Note: Limited access mode - some features may be restricted.\n";
        }
        
        // Show additional context if educational mode is enabled
        if (app.config().show_educational_info) {
            std::cout << "\nEducational Note:\n";
            std::cout << "Successfully obtained task port using task_for_pid() system call.\n";
            std::cout << "This enables memory introspection through Mach VM APIs.\n";
        }
    } else {
        std::cout << "Failed to attach to PID " << pid << ".\n";
        const auto& error = app.getLastError();
        if (!error.empty()) {
            std::cout << "  Details: " << error << '\n';
        }
        std::cout << "Use 'security " << pid << "' for detailed security analysis.\n";
    }
}

void handleStatus(const Application& app)
{
    if (const auto info = app.processManager().currentProcess()) {
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
        const auto monitored = app.valueMonitor().tracked();
        std::cout << "\n=== Monitoring Status ===\n";
        std::cout << "Monitored Addresses: " << monitored.size() << "\n";
        
    } else {
        std::cout << "No process attached.\n";
        std::cout << "Use 'attach <pid>' or 'attach self' to attach to a process.\n";
        std::cout << "Use 'processes' to see available processes.\n";
    }
}

void handleRegions(Application& app, bool show_educational = false)
{
    const auto info = app.processManager().currentProcess();
    if (!info) {
        std::cout << "No process attached.\n";
        return;
    }

    const auto regions = app.memoryScanner().enumerate(info->task_port);
    
    std::cout << "=== Memory Regions for PID " << info->pid << " ===\n";
    std::cout << "Process: " << getProcessName(info->pid) << "\n";
    std::cout << "Total regions: " << regions.size() << "\n\n";
    
    if (show_educational) {
        std::cout << "Educational Mode: Detailed explanations included\n";
        std::cout << "Format: [Start - End] Size Protection Type\n\n";
    } else {
        std::cout << "Format: [Start - End] Size Protection Type\n";
        std::cout << "Use 'regions-edu' for educational explanations\n\n";
    }
    
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
            printRegion(region, show_educational);
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
    
    if (show_educational) {
        std::cout << "\nEducational Note:\n";
        std::cout << "This demonstrates how macOS organizes process memory into distinct regions\n";
        std::cout << "with different purposes and protection levels. The kernel manages these\n";
        std::cout << "regions through the Mach VM subsystem, providing process isolation and security.\n";
    }
}

void handleSearch(Application& app, const std::string& type_token, const std::string& value_token, bool show_educational = false, bool fast_search = true)
{
    const auto info = app.processManager().currentProcess();
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
    
    if (show_educational) {
        std::cout << "\nEducational Note:\n";
        std::cout << "This search uses mach_vm_read_overwrite() to scan readable memory regions.\n";
        std::cout << "The search is performed in chunks to optimize performance and minimize\n";
        std::cout << "system call overhead. Only regions with read permissions are scanned.\n";
        if (fast_search) {
            std::cout << "Fast search focuses on regions where user data is typically stored.\n";
        }
        std::cout << "\n";
    }

    const auto results = fast_search ? 
        app.memoryScanner().searchFast(info->task_port, *value) :
        app.memoryScanner().search(info->task_port, *value);
        
    if (results.empty()) {
        std::cout << "No matches found.\n";
        if (fast_search) {
            std::cout << "Try 'search-all " << type_token << " " << value_token << "' for a complete search.\n";
        }
        if (show_educational) {
            std::cout << "\nPossible reasons:\n";
            std::cout << "• Value doesn't exist in memory\n";
            std::cout << "• Value is in a protected/unreadable region\n";
            std::cout << "• Value has different byte representation (endianness)\n";
            std::cout << "• Value is stored in a different data type\n";
            if (fast_search) {
                std::cout << "• Value is in a region not searched by fast mode (try search-all)\n";
            }
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
    const auto regions = app.memoryScanner().enumerate(info->task_port);
    
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
        
        if (show_educational) {
            std::cout << "      └─ This address can be monitored or modified (if writable)\n";
        }
        std::cout << "\n";
    }
    
    if (results.size() > display_count) {
        std::cout << "  ... " << (results.size() - display_count) << " more results not shown.\n\n";
    }
    
    if (show_educational) {
        std::cout << "Next steps:\n";
        std::cout << "• Use 'monitor add <address> <size>' to track changes\n";
        std::cout << "• Use 'write <address> <type> <value>' to modify (if writable)\n";
        std::cout << "• Use 'regions' to see memory layout\n\n";
        
        std::cout << "Memory Search Concepts:\n";
        std::cout << "• Virtual memory is searched in page-aligned chunks\n";
        std::cout << "• Only readable regions are accessible\n";
        std::cout << "• Byte order (endianness) affects how values are stored\n";
        std::cout << "• Different data types have different memory representations\n";
    }
}

void handleMonitorAdd(Application& app, const std::string& address_token, const std::string& size_token)
{
    const auto info = app.processManager().currentProcess();
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

    if (app.valueMonitor().addAddress(address, size)) {
        std::cout << "Added address 0x" << std::hex << address << std::dec
                  << " (" << size << " bytes) to monitor list.\n";
    } else {
        std::cout << "Failed to add address: maximum number of monitored addresses reached.\n";
        std::cout << "Use 'monitor clear' to remove existing addresses.\n";
    }
}

void handleMonitorList(Application& app, bool show_educational = false)
{
    const auto list = app.valueMonitor().tracked();
    if (list.empty()) {
        std::cout << "No addresses being monitored.\n";
        if (show_educational) {
            std::cout << "\nEducational Note:\n";
            std::cout << "Memory monitoring allows real-time observation of value changes.\n";
            std::cout << "Use 'monitor add <address> <size>' to start monitoring an address.\n";
        }
        return;
    }

    std::cout << "=== Monitored Memory Addresses ===\n";
    std::cout << "Total addresses: " << list.size() << "\n\n";
    
    if (show_educational) {
        std::cout << "Educational Mode: Monitoring demonstrates real-time memory observation\n\n";
    }

    // Get current process info for region context
    const auto info = app.processManager().currentProcess();
    std::vector<MemoryRegion> regions;
    if (info) {
        regions = app.memoryScanner().enumerate(info->task_port);
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
        
        if (show_educational) {
            std::cout << "      └─ Periodically read to detect changes using mach_vm_read_overwrite()\n";
        }
        std::cout << "\n";
    }
    
    if (show_educational) {
        std::cout << "Memory Monitoring Concepts:\n";
        std::cout << "• Polling: Periodically reading memory to detect changes\n";
        std::cout << "• Comparison: Storing previous values to identify modifications\n";
        std::cout << "• Performance: Balance between update frequency and CPU usage\n";
        std::cout << "• Use cases: Debugging, reverse engineering, understanding program behavior\n\n";
        
        std::cout << "Commands:\n";
        std::cout << "• 'monitor poll' - Check for changes now\n";
        std::cout << "• 'monitor clear' - Remove all monitored addresses\n";
    }
}

void handleMonitorPoll(Application& app)
{
    const auto info = app.processManager().currentProcess();
    if (!info) {
        std::cout << "No process attached.\n";
        return;
    }

    auto changes = app.valueMonitor().poll(info->task_port);
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

void handleProcesses()
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

void handleSecurity(const std::string& pid_str)
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

void handleEntitlements()
{
    SecurityManager security_manager;
    std::cout << security_manager.getEntitlementsGuidance() << "\n";
}

void handleSIPStatus()
{
    SecurityManager security_manager;
    
    std::cout << "=== System Integrity Protection Status ===\n";
    
    // This is a simplified check - in a real implementation, you'd check SIP status
    std::cout << "SIP is a macOS security feature that protects system processes.\n";
    std::cout << "CheatEngine can only attach to processes you own.\n";
    std::cout << "System processes and processes owned by other users are protected.\n\n";
    
    std::cout << "To check full SIP status, run in Terminal:\n";
    std::cout << "  csrutil status\n\n";
    
    std::cout << "Educational Note:\n";
    std::cout << "SIP demonstrates defense-in-depth security principles by:\n";
    std::cout << "- Protecting critical system processes from modification\n";
    std::cout << "- Enforcing process isolation boundaries\n";
    std::cout << "- Requiring explicit permissions for debugging access\n";
}

void handleWrite(Application& app, const std::string& address_str, const std::string& type_str, const std::string& value_str)
{
    const auto info = app.processManager().currentProcess();
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
    if (app.config().require_confirmation_for_writes) {
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
    if (app.performSecureMemoryWrite(address, data)) {
        if (app.config().show_educational_info) {
            std::cout << "Educational Note: Memory write demonstrates direct process memory modification\n";
            std::cout << "using mach_vm_write() system call with proper permission validation.\n";
        }
    } else {
        std::cout << "Failed to write to address 0x" << std::hex << address << std::dec << "\n";
        const auto& error = app.getLastError();
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

void handleMonitorClear(Application& app)
{
    app.valueMonitor().clear();
    std::cout << "Cleared all monitored addresses.\n";
}

void handleMemoryConcepts()
{
    std::cout << "\n=== Virtual Memory Concepts ===\n\n";
    
    std::cout << "1. Virtual Address Space:\n";
    std::cout << "   • Each process has its own virtual address space\n";
    std::cout << "   • On 64-bit macOS, this is typically 48-bit addressing (256 TB)\n";
    std::cout << "   • Virtual addresses are translated to physical addresses by the MMU\n";
    std::cout << "   • Provides process isolation and memory protection\n\n";
    
    std::cout << "2. Memory Pages:\n";
    std::cout << "   • Memory is managed in fixed-size pages (typically 4KB on x86_64)\n";
    std::cout << "   • Pages can be mapped, unmapped, or have different protection levels\n";
    std::cout << "   • Page faults occur when accessing unmapped or protected pages\n";
    std::cout << "   • Demand paging loads pages from disk when needed\n\n";
    
    std::cout << "3. Memory Layout (typical macOS process):\n";
    std::cout << "   High addresses: Stack (grows downward)\n";
    std::cout << "                   ↓\n";
    std::cout << "                   Shared libraries (dylibs)\n";
    std::cout << "                   Heap (grows upward)\n";
    std::cout << "                   ↑\n";
    std::cout << "                   Data segment (globals, statics)\n";
    std::cout << "   Low addresses:  Code segment (executable)\n\n";
    
    std::cout << "4. Memory Protection:\n";
    std::cout << "   • Read (r): Can read memory contents\n";
    std::cout << "   • Write (w): Can modify memory contents\n";
    std::cout << "   • Execute (x): Can execute code from memory\n";
    std::cout << "   • NX bit prevents code execution from data pages\n\n";
    
    std::cout << "5. Copy-on-Write (COW):\n";
    std::cout << "   • Shared pages are marked read-only initially\n";
    std::cout << "   • Writing triggers a copy to private memory\n";
    std::cout << "   • Optimizes memory usage for shared libraries\n\n";
}

void handleMachAPIs()
{
    std::cout << "\n=== Mach Kernel APIs ===\n\n";
    
    std::cout << "CheatEngine uses several Mach kernel APIs for memory introspection:\n\n";
    
    std::cout << "1. task_for_pid(mach_task_self(), pid, &task):\n";
    std::cout << "   • Obtains a task port for the target process\n";
    std::cout << "   • Requires proper entitlements (com.apple.security.get-task-allow)\n";
    std::cout << "   • Task port is needed for all memory operations\n";
    std::cout << "   • Returns KERN_SUCCESS on success\n\n";
    
    std::cout << "2. mach_vm_region(task, &address, &size, flavor, info, &count, &object):\n";
    std::cout << "   • Enumerates memory regions in the target process\n";
    std::cout << "   • Returns region start, size, and protection information\n";
    std::cout << "   • Used to discover the memory layout\n";
    std::cout << "   • Iteratively called to scan entire address space\n\n";
    
    std::cout << "3. mach_vm_read_overwrite(task, address, size, data, &data_count):\n";
    std::cout << "   • Reads memory contents from the target process\n";
    std::cout << "   • More efficient than mach_vm_read for large reads\n";
    std::cout << "   • Requires read permissions on the target region\n";
    std::cout << "   • Used for memory scanning and monitoring\n\n";
    
    std::cout << "4. mach_vm_write(task, address, data, data_count):\n";
    std::cout << "   • Writes data to the target process memory\n";
    std::cout << "   • Requires write permissions on the target region\n";
    std::cout << "   • Can modify program behavior and data\n";
    std::cout << "   • Use with caution - can crash the target process\n\n";
    
    std::cout << "Error Handling:\n";
    std::cout << "• All Mach APIs return kern_return_t status codes\n";
    std::cout << "• KERN_SUCCESS (0) indicates success\n";
    std::cout << "• Common errors: KERN_INVALID_ADDRESS, KERN_PROTECTION_FAILURE\n";
    std::cout << "• Always check return values and handle errors appropriately\n\n";
}

void handleSecurityModel()
{
    std::cout << "\n=== macOS Security Model ===\n\n";
    
    std::cout << "1. Process Isolation:\n";
    std::cout << "   • Each process runs in its own virtual address space\n";
    std::cout << "   • Hardware MMU enforces memory protection boundaries\n";
    std::cout << "   • Processes cannot directly access each other's memory\n";
    std::cout << "   • Inter-process communication requires explicit mechanisms\n\n";
    
    std::cout << "2. Code Signing:\n";
    std::cout << "   • All executables must be signed with a valid certificate\n";
    std::cout << "   • Signature includes cryptographic hash of code pages\n";
    std::cout << "   • Kernel verifies signatures before execution\n";
    std::cout << "   • Prevents execution of modified or malicious code\n\n";
    
    std::cout << "3. Entitlements:\n";
    std::cout << "   • Special permissions embedded in code signatures\n";
    std::cout << "   • Control access to restricted APIs and resources\n";
    std::cout << "   • 'get-task-allow' enables debugging/introspection\n";
    std::cout << "   • 'cs.debugger' allows attaching to other processes\n\n";
    
    std::cout << "4. System Integrity Protection (SIP):\n";
    std::cout << "   • Protects critical system files and processes\n";
    std::cout << "   • Prevents modification even by root user\n";
    std::cout << "   • Blocks task_for_pid on system processes\n";
    std::cout << "   • Can be disabled for development (not recommended)\n\n";
    
    std::cout << "5. Sandboxing:\n";
    std::cout << "   • Restricts process capabilities and file system access\n";
    std::cout << "   • App Store apps run in strict sandboxes\n";
    std::cout << "   • Limits network access and hardware interaction\n";
    std::cout << "   • Provides defense-in-depth security\n\n";
    
    std::cout << "6. Address Space Layout Randomization (ASLR):\n";
    std::cout << "   • Randomizes memory layout on each execution\n";
    std::cout << "   • Makes exploitation more difficult\n";
    std::cout << "   • Stack, heap, and library locations vary\n";
    std::cout << "   • Observe different addresses when restarting processes\n\n";
}

void handleConfigShow(const Application& app)
{
    const auto& config = app.config();
    
    std::cout << "=== Current Configuration ===\n\n";
    
    std::cout << "Search Settings:\n";
    std::cout << "  max_search_results: " << config.max_search_results << "\n";
    std::cout << "  search_chunk_size: " << config.search_chunk_size << " bytes\n\n";
    
    std::cout << "Monitoring Settings:\n";
    std::cout << "  monitor_interval: " << config.monitor_interval.count() << " ms\n";
    std::cout << "  max_monitored_addresses: " << config.max_monitored_addresses << "\n\n";
    
    std::cout << "Display Settings:\n";
    std::cout << "  show_educational_info: " << (config.show_educational_info ? "true" : "false") << "\n";
    std::cout << "  verbose_errors: " << (config.verbose_errors ? "true" : "false") << "\n";
    std::cout << "  context_bytes: " << config.context_bytes << "\n\n";
    
    std::cout << "Security Settings:\n";
    std::cout << "  enable_memory_writing: " << (config.enable_memory_writing ? "true" : "false") << "\n";
    std::cout << "  require_confirmation_for_writes: " << (config.require_confirmation_for_writes ? "true" : "false") << "\n\n";
    
    std::cout << "Performance Settings:\n";
    std::cout << "  memory_read_timeout_ms: " << config.memory_read_timeout_ms << " ms\n";
    std::cout << "  use_chunked_reading: " << (config.use_chunked_reading ? "true" : "false") << "\n\n";
}

void handleConfigSet(Application& app, const std::string& key, const std::string& value)
{
    auto& config = app.config();
    
    try {
        if (key == "max_search_results") {
            config.max_search_results = std::stoul(value);
        } else if (key == "search_chunk_size") {
            config.search_chunk_size = std::stoul(value);
        } else if (key == "monitor_interval") {
            config.monitor_interval = std::chrono::milliseconds(std::stoul(value));
        } else if (key == "max_monitored_addresses") {
            config.max_monitored_addresses = std::stoul(value);
        } else if (key == "show_educational_info") {
            config.show_educational_info = (value == "true" || value == "1" || value == "yes");
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
        
    } catch (const std::exception& e) {
        std::cout << "Invalid value for " << key << ": " << e.what() << "\n";
    }
}

void handleConfigReset(Application& app)
{
    app.config() = ApplicationConfig{};
    std::cout << "Configuration reset to defaults.\n";
}

} // namespace

int main()
{
    Application app;
    
    // Initialize the application
    if (!app.initialize()) {
        std::cerr << "Failed to initialize CheatEngine: " << app.getLastError() << std::endl;
        return 1;
    }
    
    // Load configuration (using defaults for now)
    app.loadConfig();
    
    std::cout << "=== CheatEngine - Educational Memory Analysis Tool ===\n";
    std::cout << "A tool for learning macOS memory management and security concepts.\n";
    std::cout << "Type 'help' for commands or 'troubleshoot' for security guidance.\n";
    
    // Show configuration status
    const auto& config = app.config();
    std::cout << "\nConfiguration:\n";
    std::cout << "• Educational mode: " << (config.show_educational_info ? "enabled" : "disabled") << "\n";
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
                handleAttach(app, target);
            } else if (command == "detach") {
                app.detachWithCleanup();
                std::cout << "Detached from process and cleaned up resources.\n";
            } else if (command == "status") {
                handleStatus(app);
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
                handleRegions(app, false);
            } else if (command == "regions-edu") {
                handleRegions(app, true);
            } else if (command == "search") {
                std::string type_token;
                std::string value_token;
                if (!(iss >> type_token >> value_token)) {
                    std::cout << "Usage: search <type> <value>\n";
                    std::cout << "Types: int32, int64, float, double\n";
                    std::cout << "Example: search int32 42\n";
                    continue;
                }
                handleSearch(app, type_token, value_token, false, true); // Fast search by default
            } else if (command == "search-all") {
                std::string type_token;
                std::string value_token;
                if (!(iss >> type_token >> value_token)) {
                    std::cout << "Usage: search-all <type> <value>\n";
                    std::cout << "Types: int32, int64, float, double\n";
                    std::cout << "Example: search-all int32 42\n";
                    continue;
                }
                handleSearch(app, type_token, value_token, false, false); // Complete search
            } else if (command == "search-edu") {
                std::string type_token;
                std::string value_token;
                if (!(iss >> type_token >> value_token)) {
                    std::cout << "Usage: search-edu <type> <value>\n";
                    std::cout << "Types: int32, int64, float, double\n";
                    std::cout << "Example: search-edu int32 42\n";
                    continue;
                }
                handleSearch(app, type_token, value_token, true, true); // Educational fast search
            } else if (command == "write") {
                std::string address_str, type_str, value_str;
                if (!(iss >> address_str >> type_str >> value_str)) {
                    std::cout << "Usage: write <address> <type> <value>\n";
                    std::cout << "Example: write 0x7fff5fbff000 int32 42\n";
                    continue;
                }
                handleWrite(app, address_str, type_str, value_str);
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
                    handleMonitorAdd(app, address_token, size_token);
                } else if (subcommand == "list") {
                    handleMonitorList(app, false);
                } else if (subcommand == "list-edu") {
                    handleMonitorList(app, true);
                } else if (subcommand == "poll") {
                    handleMonitorPoll(app);
                } else if (subcommand == "clear") {
                    handleMonitorClear(app);
                } else {
                    std::cout << "Unknown monitor command. Use: add, list, poll, clear\n";
                }
            } else if (command == "troubleshoot") {
                printTroubleshootingGuide();
            } else if (command == "entitlements") {
                handleEntitlements();
            } else if (command == "sip-status") {
                handleSIPStatus();
            } else if (command == "memory-concepts") {
                handleMemoryConcepts();
            } else if (command == "mach-apis") {
                handleMachAPIs();
            } else if (command == "security-model") {
                handleSecurityModel();
            } else if (command == "config") {
                std::string subcommand;
                if (!(iss >> subcommand)) {
                    std::cout << "Usage: config <show|set|reset>\n";
                    continue;
                }
                if (subcommand == "show") {
                    handleConfigShow(app);
                } else if (subcommand == "set") {
                    std::string key, value;
                    if (!(iss >> key >> value)) {
                        std::cout << "Usage: config set <key> <value>\n";
                        continue;
                    }
                    handleConfigSet(app, key, value);
                } else if (subcommand == "reset") {
                    handleConfigReset(app);
                } else {
                    std::cout << "Unknown config command. Use: show, set, reset\n";
                }
            } else if (command == "quit" || command == "exit") {
                std::cout << "Shutting down CheatEngine...\n";
                app.shutdown();
                std::cout << "Thank you for learning about memory management!\n";
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
    
    // Ensure proper shutdown even if user doesn't use quit command
    if (app.isInitialized()) {
        app.shutdown();
    }

    return 0;
}
