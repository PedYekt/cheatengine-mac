#pragma once

#include "cheatengine/core/application.hpp"
#include <string>

namespace cheatengine {
namespace cli {

class CommandLineInterface {
public:
    CommandLineInterface(Application& app);
    void run();

private:
    Application& app_;

    void printHelp() const;
    void handleAttach(const std::string& target);
    void handleDetach();
    void handleStatus() const;
    void handleProcesses() const;
    void handleSecurity(const std::string& pid_str) const;
    void handleRegions() const;
    void handleSearch(const std::string& type, const std::string& value, bool fast);
    void handleWrite(const std::string& addr, const std::string& type, const std::string& value);
    void handleMonitorAdd(const std::string& addr, const std::string& size);
    void handleMonitorList() const;
    void handleMonitorPoll();
    void handleMonitorClear();
};

} // namespace cli
} // namespace cheatengine
