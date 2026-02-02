#include "cheatengine/cli/command_line_interface.hpp"
#include "cheatengine/memory/memory_region.hpp"
#include "cheatengine/memory/value_types.hpp"
#include "cheatengine/process/security_manager.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <unistd.h>
#include <libproc.h>

namespace cheatengine {
namespace cli {

namespace {

std::string bytesToHex(const std::vector<std::uint8_t>& bytes, std::size_t max_count)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < std::min(bytes.size(), max_count); ++i) {
        oss << std::setw(2) << static_cast<int>(bytes[i]) << ' ';
    }
    if (bytes.size() > max_count) oss << "...";
    return oss.str();
}

std::optional<SearchValue> parseSearchValue(const std::string& type, const std::string& val)
{
    try {
        if (type == "int32") return SearchValue::fromInt32(static_cast<std::int32_t>(std::stol(val, nullptr, 0)));
        if (type == "int64") return SearchValue::fromInt64(static_cast<std::int64_t>(std::stoll(val, nullptr, 0)));
        if (type == "float") return SearchValue::fromFloat32(std::stof(val));
        if (type == "double") return SearchValue::fromFloat64(std::stod(val));
    } catch (...) {}
    return std::nullopt;
}

std::string getProcessName(pid_t pid)
{
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, path, sizeof(path)) <= 0) return "Unknown";
    std::string full(path);
    auto pos = full.find_last_of('/');
    return (pos != std::string::npos) ? full.substr(pos + 1) : full;
}

} // namespace

CommandLineInterface::CommandLineInterface(Application& app) : app_(app) {}

void CommandLineInterface::run()
{
    std::cout << "CheatEngine - Memory Analysis Tool\nType 'help' for commands.\n\n";

    std::string line;
    while (true) {
        std::cout << "cheatengine> " << std::flush;
        if (!std::getline(std::cin, line)) break;

        std::istringstream iss(line);
        std::string cmd;
        if (!(iss >> cmd)) continue;

        if (cmd == "help") {
            printHelp();
        } else if (cmd == "attach") {
            std::string target;
            if (!(iss >> target)) { std::cout << "Usage: attach <pid|self>\n"; continue; }
            handleAttach(target);
        } else if (cmd == "detach") {
            handleDetach();
        } else if (cmd == "status") {
            handleStatus();
        } else if (cmd == "processes") {
            handleProcesses();
        } else if (cmd == "security") {
            std::string pid_str;
            if (!(iss >> pid_str)) { std::cout << "Usage: security <pid>\n"; continue; }
            handleSecurity(pid_str);
        } else if (cmd == "regions") {
            handleRegions();
        } else if (cmd == "search" || cmd == "search-all") {
            std::string type, val;
            if (!(iss >> type >> val)) { std::cout << "Usage: search <type> <value>\n"; continue; }
            handleSearch(type, val, cmd == "search");
        } else if (cmd == "write") {
            std::string addr, type, val;
            if (!(iss >> addr >> type >> val)) { std::cout << "Usage: write <addr> <type> <value>\n"; continue; }
            handleWrite(addr, type, val);
        } else if (cmd == "monitor") {
            std::string sub;
            if (!(iss >> sub)) { std::cout << "Usage: monitor <add|list|poll|clear>\n"; continue; }
            if (sub == "add") {
                std::string addr, sz;
                if (!(iss >> addr >> sz)) { std::cout << "Usage: monitor add <addr> <size>\n"; continue; }
                handleMonitorAdd(addr, sz);
            } else if (sub == "list") handleMonitorList();
            else if (sub == "poll") handleMonitorPoll();
            else if (sub == "clear") handleMonitorClear();
        } else if (cmd == "quit" || cmd == "exit") {
            std::cout << "Goodbye.\n";
            break;
        } else {
            std::cout << "Unknown command. Type 'help'.\n";
        }
        std::cout << "\n";
    }
}

void CommandLineInterface::printHelp() const
{
    std::cout << "Commands:\n"
        "  attach <pid|self>     Attach to process\n"
        "  detach                Detach from process\n"
        "  status                Show current status\n"
        "  processes             List available processes\n"
        "  security <pid>        Check security for PID\n"
        "  regions               List memory regions\n"
        "  search <type> <val>   Fast search (stack/heap/data)\n"
        "  search-all <type> <val> Full search\n"
        "  write <addr> <type> <val> Write to memory\n"
        "  monitor add <addr> <size> Add monitor\n"
        "  monitor list          List monitors\n"
        "  monitor poll          Poll for changes\n"
        "  monitor clear         Clear monitors\n"
        "  quit                  Exit\n";
}

void CommandLineInterface::handleAttach(const std::string& target)
{
    pid_t pid = (target == "self") ? getpid() : static_cast<pid_t>(std::stol(target, nullptr, 0));

    std::cout << "Attaching to " << getProcessName(pid) << " (PID " << pid << ")...\n";

    if (app_.attachToProcessWithValidation(pid)) {
        std::cout << "Attached.\n";
    } else {
        std::cout << "Failed: " << app_.getLastError() << "\n";
    }
}

void CommandLineInterface::handleDetach()
{
    app_.detachWithCleanup();
    std::cout << "Detached.\n";
}

void CommandLineInterface::handleStatus() const
{
    auto info = app_.processManager().currentProcess();
    if (!info) {
        std::cout << "No process attached.\n";
        return;
    }

    std::cout << "PID: " << info->pid << "\n";
    std::cout << "Name: " << getProcessName(info->pid) << "\n";
    std::cout << "Task port: " << (info->task_port != MACH_PORT_NULL ? "Valid" : "Invalid") << "\n";
    std::cout << "Monitored: " << app_.valueMonitor().tracked().size() << " addresses\n";
}

void CommandLineInterface::handleProcesses() const
{
    int num_pids = proc_listallpids(nullptr, 0);
    if (num_pids <= 0) { std::cout << "Failed to list processes.\n"; return; }

    std::vector<pid_t> pids(num_pids);
    num_pids = proc_listallpids(pids.data(), num_pids * sizeof(pid_t));

    SecurityManager sm;
    uid_t uid = getuid();
    int count = 0;

    std::cout << "PID     Name                    Access\n";
    std::cout << "--------------------------------------\n";

    for (int i = 0; i < num_pids && count < 50; ++i) {
        pid_t pid = pids[i];
        if (pid <= 0) continue;

        struct proc_bsdinfo info;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) <= 0) continue;
        if (info.pbi_uid != uid) continue;

        auto access = sm.evaluateProcessAccess(pid);
        if (access.level == SecurityManager::AccessLevel::NO_ACCESS) continue;

        std::cout << std::left << std::setw(8) << pid
                  << std::setw(24) << getProcessName(pid).substr(0, 23)
                  << (access.level == SecurityManager::AccessLevel::FULL_ACCESS ? "Full" : "Limited")
                  << "\n";
        count++;
    }
}

void CommandLineInterface::handleSecurity(const std::string& pid_str) const
{
    pid_t pid = static_cast<pid_t>(std::stol(pid_str, nullptr, 0));
    SecurityManager sm;

    std::cout << "PID: " << pid << " (" << getProcessName(pid) << ")\n";
    std::cout << "System process: " << (sm.isSystemProcess(pid) ? "Yes" : "No") << "\n";
    std::cout << "SIP protected: " << (sm.isSIPProtected(pid) ? "Yes" : "No") << "\n";

    auto info = sm.evaluateProcessAccess(pid);
    std::cout << "Access: ";
    switch (info.level) {
        case SecurityManager::AccessLevel::FULL_ACCESS: std::cout << "Full\n"; break;
        case SecurityManager::AccessLevel::LIMITED_ACCESS: std::cout << "Limited\n"; break;
        default: std::cout << "None\n"; break;
    }
    if (!info.restriction_reason.empty()) {
        std::cout << "Reason: " << info.restriction_reason << "\n";
    }
}

void CommandLineInterface::handleRegions() const
{
    auto info = app_.processManager().currentProcess();
    if (!info) { std::cout << "No process attached.\n"; return; }

    auto regions = app_.memoryScanner().enumerate(info->task_port);
    std::cout << "Regions: " << regions.size() << "\n\n";

    for (const auto& r : regions) {
        std::cout << std::hex << "0x" << r.start_address << "-0x" << r.endAddress()
                  << std::dec << " " << r.sizeString() << " " << r.flags().toString()
                  << " " << r.category << "\n";
    }
}

void CommandLineInterface::handleSearch(const std::string& type, const std::string& val, bool fast)
{
    auto info = app_.processManager().currentProcess();
    if (!info) { std::cout << "No process attached.\n"; return; }

    auto value = parseSearchValue(type, val);
    if (!value) { std::cout << "Invalid type/value. Use: int32, int64, float, double\n"; return; }

    auto results = fast ?
        app_.memoryScanner().searchFast(info->task_port, *value) :
        app_.memoryScanner().search(info->task_port, *value);

    if (results.empty()) { std::cout << "No matches.\n"; return; }

    std::cout << "Found " << results.size() << " matches:\n";
    for (std::size_t i = 0; i < std::min(results.size(), std::size_t{20}); ++i) {
        std::cout << "  0x" << std::hex << results[i].address << std::dec << "\n";
    }
}

void CommandLineInterface::handleWrite(const std::string& addr_str, const std::string& type, const std::string& val_str)
{
    auto info = app_.processManager().currentProcess();
    if (!info) { std::cout << "No process attached.\n"; return; }

    auto addr = static_cast<mach_vm_address_t>(std::stoull(addr_str, nullptr, 0));
    auto value = parseSearchValue(type, val_str);
    if (!value) { std::cout << "Invalid type/value.\n"; return; }

    if (!app_.performSecureMemoryWrite(addr, value->data())) {
        std::cout << "Write failed: " << app_.getLastError() << "\n";
    } else {
        std::cout << "Written.\n";
    }
}

void CommandLineInterface::handleMonitorAdd(const std::string& addr_str, const std::string& size_str)
{
    if (!app_.processManager().currentProcess()) { std::cout << "No process attached.\n"; return; }

    auto addr = static_cast<mach_vm_address_t>(std::stoull(addr_str, nullptr, 0));
    auto size = static_cast<std::size_t>(std::stoul(size_str, nullptr, 0));

    if (app_.valueMonitor().addAddress(addr, size)) {
        std::cout << "Added 0x" << std::hex << addr << std::dec << " (" << size << " bytes)\n";
    } else {
        std::cout << "Failed to add (max reached?)\n";
    }
}

void CommandLineInterface::handleMonitorList() const
{
    auto list = app_.valueMonitor().tracked();
    if (list.empty()) { std::cout << "No monitors.\n"; return; }

    for (const auto& e : list) {
        std::cout << "0x" << std::hex << e.address << std::dec << " (" << e.value_size << " bytes)\n";
    }
}

void CommandLineInterface::handleMonitorPoll()
{
    auto info = app_.processManager().currentProcess();
    if (!info) { std::cout << "No process attached.\n"; return; }

    auto changes = app_.valueMonitor().poll(info->task_port);
    if (changes.empty()) { std::cout << "No changes.\n"; return; }

    for (const auto& c : changes) {
        std::cout << "0x" << std::hex << c.address << std::dec
                  << " old:" << bytesToHex(c.old_value, 16)
                  << " new:" << bytesToHex(c.new_value, 16) << "\n";
    }
}

void CommandLineInterface::handleMonitorClear()
{
    app_.valueMonitor().clear();
    std::cout << "Cleared.\n";
}

} // namespace cli
} // namespace cheatengine
