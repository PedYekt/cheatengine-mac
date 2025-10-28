#include <atomic>
#include <chrono>
#include <csignal>
#include <iomanip>
#include <iostream>
#include <thread>
#include <unistd.h>

namespace {
std::atomic<bool> g_running{true};

void handleSignal(int)
{
    g_running.store(false);
}
} // namespace

int main()
{
    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    std::atomic<int> counter{0};

    std::cout << "Counter sample running. PID: " << getpid() << std::endl;
    while (g_running.load()) {
        const int value = ++counter;
        std::cout << "counter: " << std::setw(10) << value << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    std::cout << "Counter sample exiting." << std::endl;
    return 0;
}
