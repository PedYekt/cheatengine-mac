#pragma once

#include "cheatengine/core/application.hpp"
#include <string>

namespace cheatengine {
namespace cli {

class CommandLineInterface {
public:
    explicit CommandLineInterface(Application& app);
    
    // Main loop
    void run();

private:
    Application& app_;

    // Command handlers
    void printHelp() const;
    void handleAttach(const std::string& target);
    void handleDetach();
    void handleStatus() const;
    void handleProcesses() const;
    void handleSecurity(const std::string& pid_str) const;
    void handleRegions(bool show_educational) const;
    void handleSearch(const std::string& type_token, const std::string& value_token, bool show_educational, bool fast_search);
    void handleWrite(const std::string& address_str, const std::string& type_str, const std::string& value_str);
    void handleMonitorAdd(const std::string& address_token, const std::string& size_token);
    void handleMonitorList(bool show_educational) const;
    void handleMonitorPoll();
    void handleMonitorClear();
    
    // Educational & Info handlers
    void handleTroubleshoot() const;
    void handleEntitlements() const;
    void handleSIPStatus() const;
    void handleMemoryConcepts() const;
    void handleMachAPIs() const;
    void handleSecurityModel() const;
    
    // Config handlers
    void handleConfigShow() const;
    void handleConfigSet(const std::string& key, const std::string& value);
    void handleConfigReset();
};

} // namespace cli
} // namespace cheatengine
