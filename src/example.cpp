#include "netctrl.hpp"
#include <iostream>
#include <string>
#include <sstream>
#include <csignal>

netctrl::NetCtrl* g_ctrl = nullptr;

void cleanup(int) {
    std::cout << "\n\nRestoring network..." << std::endl;
    if (g_ctrl) g_ctrl->disable();
    exit(0);
}

int main() {
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    
    if (!netctrl::NetCtrl::isAdmin()) {
        std::cerr << "ERROR: Need root/admin privileges!\n";
        std::cerr << "Run with: sudo ./example\n";
        return 1;
    }
    
    netctrl::NetCtrl ctrl;
    g_ctrl = &ctrl;
    
    std::cout << "╔════════════════════════════════════════╗" << std::endl;
    std::cout << "║     NetCtrl - Network Control Tool     ║" << std::endl;
    std::cout << "╚════════════════════════════════════════╝\n" << std::endl;
    
    std::cout << "⚠️  WARNING: Affects ALL network traffic!\n" << std::endl;
    
    std::cout << "Commands:" << std::endl;
    std::cout << "  block          - Block 100%" << std::endl;
    std::cout << "  lag <ms> <%>   - Apply lag + drop" << std::endl;
    std::cout << "  off            - Disable" << std::endl;
    std::cout << "  quit           - Exit\n" << std::endl;
    
    std::cout << "Examples:" << std::endl;
    std::cout << "  block          - Complete block" << std::endl;
    std::cout << "  lag 1 99.5     - Clumsy preset" << std::endl;
    std::cout << "  lag 100 50     - 100ms + 50% loss" << std::endl;
    std::cout << "  lag 200 0      - 200ms delay only" << std::endl;
    std::cout << "  lag 0 50       - 50% loss only\n" << std::endl;
    
    std::string line;
    while (true) {
        std::string status = ctrl.isActive() ? "[ACTIVE]" : "[OFF]";
        std::cout << status << " > ";
        std::cout.flush();
        
        if (!std::getline(std::cin, line)) break;
        
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        
        if (cmd == "block" || cmd == "b") {
            if (ctrl.block()) {
                std::cout << "✓ Blocked!\n" << std::endl;
            } else {
                std::cout << "✗ Failed!\n" << std::endl;
            }
        }
        else if (cmd == "lag" || cmd == "l") {
            int ms;
            double pct;
            if (iss >> ms >> pct) {
                if (ctrl.lag(ms, pct)) {
                    std::cout << "✓ Applied: " << ms << "ms + " << pct << "% drop\n" << std::endl;
                } else {
                    std::cout << "✗ Failed!\n" << std::endl;
                }
            } else {
                std::cout << "Usage: lag <ms> <%>\n" << std::endl;
            }
        }
        else if (cmd == "off" || cmd == "disable" || cmd == "d") {
            ctrl.disable();
            std::cout << "✓ Disabled\n" << std::endl;
        }
        else if (cmd == "status" || cmd == "s") {
            std::cout << "Active: " << (ctrl.isActive() ? "Yes" : "No") << std::endl;
            if (ctrl.isActive()) {
                std::cout << "Lag: " << ctrl.getLag() << "ms" << std::endl;
                std::cout << "Drop: " << ctrl.getDrop() << "%\n" << std::endl;
            }
        }
        else if (cmd == "quit" || cmd == "q") {
            break;
        }
        else {
            std::cout << "Unknown command\n" << std::endl;
        }
    }
    
    ctrl.disable();
    std::cout << "Goodbye!" << std::endl;
    return 0;
}
