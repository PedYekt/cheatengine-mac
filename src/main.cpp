#include "cheatengine/core/application.hpp"
#include "cheatengine/cli/command_line_interface.hpp"

#include <iostream>

int main()
{
    cheatengine::Application app;

    if (!app.initialize()) {
        std::cerr << "Init failed: " << app.getLastError() << std::endl;
        return 1;
    }

    cheatengine::cli::CommandLineInterface cli(app);
    cli.run();

    return 0;
}
