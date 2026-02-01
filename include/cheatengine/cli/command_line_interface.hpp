/**
 * @file command_line_interface.hpp
 * @brief Command-line interface for CheatEngine.
 */

#pragma once

#include "cheatengine/core/application.hpp"
#include <string>

namespace cheatengine {
namespace cli {

/**
 * @brief Interactive command-line interface wrapper.
 */
class CommandLineInterface {
public:
    /**
     * @brief Constructs the CLI using the provided application instance.
     * @param app Application instance to operate on.
     */
    explicit CommandLineInterface(Application& app);

    /**
     * @brief Runs the CLI loop until exit.
     */
    void run();

private:
    /** @brief Application instance used by the CLI. */
    Application& app_;

    // Command handlers
    /**
     * @brief Prints help text for available commands.
     */
    void printHelp() const;

    /**
     * @brief Attaches to a process specified by token.
     * @param target PID or "self".
     */
    void handleAttach(const std::string& target);

    /**
     * @brief Detaches from the current process.
     */
    void handleDetach();

    /**
     * @brief Prints current attachment status.
     */
    void handleStatus() const;

    /**
     * @brief Lists running processes that can be attached to.
     */
    void handleProcesses() const;

    /**
     * @brief Prints security information for a process.
     * @param pid_str PID string to inspect.
     */
    void handleSecurity(const std::string& pid_str) const;

    /**
     * @brief Lists memory regions for the attached process.
     */
    void handleRegions() const;

    /**
     * @brief Searches memory for a value.
     * @param type_token Value type token.
     * @param value_token Value token.
     * @param fast_search True for fast search; false for full search.
     */
    void handleSearch(const std::string& type_token, const std::string& value_token, bool fast_search);

    /**
     * @brief Writes a value to memory.
     * @param address_str Address token.
     * @param type_str Type token.
     * @param value_str Value token.
     */
    void handleWrite(const std::string& address_str, const std::string& type_str, const std::string& value_str);

    /**
     * @brief Adds an address to the monitor list.
     * @param address_token Address token.
     * @param size_token Size token.
     */
    void handleMonitorAdd(const std::string& address_token, const std::string& size_token);

    /**
     * @brief Lists monitored addresses.
     */
    void handleMonitorList() const;

    /**
     * @brief Polls monitored addresses for changes.
     */
    void handleMonitorPoll();

    /**
     * @brief Clears all monitored addresses.
     */
    void handleMonitorClear();

    // Info handlers
    /**
     * @brief Prints troubleshooting guidance.
     */
    void handleTroubleshoot() const;

    /**
     * @brief Prints entitlements guidance.
     */
    void handleEntitlements() const;

    /**
     * @brief Prints System Integrity Protection status guidance.
     */
    void handleSIPStatus() const;

    // Config handlers
    /**
     * @brief Prints current configuration values.
     */
    void handleConfigShow() const;

    /**
     * @brief Sets a configuration value.
     * @param key Configuration key.
     * @param value Configuration value.
     */
    void handleConfigSet(const std::string& key, const std::string& value);

    /**
     * @brief Resets configuration to defaults.
     */
    void handleConfigReset();
};

} // namespace cli
} // namespace cheatengine
