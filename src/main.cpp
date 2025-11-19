#include "cheatengine/core/application.hpp"
#include "cheatengine/cli/command_line_interface.hpp"

#include <iostream>

int main()
{
    cheatengine::Application app;
    
    // Initialize the application
    if (!app.initialize()) {
        std::cerr << "Failed to initialize CheatEngine: " << app.getLastError() << std::endl;
        return 1;
    }
    
    // Load configuration
    // Note: We'll use a default path for now
    app.loadConfig("cheatengine.conf");
    
    // Run the command line interface
    cheatengine::cli::CommandLineInterface cli(app);
    cli.run();
    
    // Ensure proper shutdown
    if (app.isInitialized()) {
        app.shutdown();
    }

    return 0;
}
