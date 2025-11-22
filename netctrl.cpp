#include "netctrl.hpp"
#include <iostream>
#include <string>
#include <csignal>

netctrl::NetCtrl* g_ctrl = nullptr;

void cleanup(int) {
    if (g_ctrl) {
        std::cout << "\nCleaning up..." << std::endl;
        g_ctrl->unblock();
    }
    exit(0);
}

int main(int argc, char* argv[]) {
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    
    if (!netctrl::NetCtrl::isAdmin()) {
        std::cerr << "ERROR: Run as administrator/root!\n";
#ifdef _WIN32
        std::cerr << "Right-click and 'Run as Administrator'\n";
#else
        std::cerr << "Use: sudo ./example\n";
#endif
        return 1;
    }
    
    std::string target = (argc > 1) ? argv[1] : "sober";
    
    netctrl::NetCtrl ctrl("netctrl");
    g_ctrl = &ctrl;
    
    std::cout << "╔══════════════════════════════════════════╗" << std::endl;
    std::cout << "║   NetCtrl - Network Traffic Blocker     ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════╝" << std::endl;
    std::cout << "\nTarget process: " << target << std::endl;
    std::cout << "\nCommands:" << std::endl;
    std::cout << "  block-out / bo  - Block OUTBOUND traffic (default)" << std::endl;
    std::cout << "  block-in  / bi  - Block INBOUND traffic" << std::endl;
    std::cout << "  block     / b   - Block BOTH directions" << std::endl;
    std::cout << "  unblock   / u   - Unblock everything" << std::endl;
    std::cout << "  status    / s   - Show status" << std::endl;
    std::cout << "  quit      / q   - Exit\n" << std::endl;
    
    std::string cmd;
    while (true) {
        std::string status;
        if (ctrl.isBlockedOutbound() && ctrl.isBlockedInbound()) {
            status = "[BLOCKED ⬆⬇]";
        } else if (ctrl.isBlockedOutbound()) {
            status = "[BLOCKED ⬆]";
        } else if (ctrl.isBlockedInbound()) {
            status = "[BLOCKED ⬇]";
        } else {
            status = "[UNBLOCKED]";
        }
        
        std::cout << status << " > ";
        std::cout.flush();
        
        if (!std::getline(std::cin, cmd)) break;
        
        cmd.erase(0, cmd.find_first_not_of(" \t\n\r"));
        cmd.erase(cmd.find_last_not_of(" \t\n\r") + 1);
        
        if (cmd.empty()) continue;
        
        if (cmd == "block-out" || cmd == "bo") {
            if (ctrl.isBlockedOutbound()) {
                std::cout << "Outbound already blocked!" << std::endl;
            } else {
                std::cout << "Blocking OUTBOUND traffic..." << std::endl;
                if (ctrl.blockOutbound(target)) {
                    std::cout << "✓ OUTBOUND BLOCKED! (Process can't send data)\n" << std::endl;
                } else {
                    std::cout << "✗ Failed! Is the process running?\n" << std::endl;
                }
            }
        }
        else if (cmd == "block-in" || cmd == "bi") {
            if (ctrl.isBlockedInbound()) {
                std::cout << "Inbound already blocked!" << std::endl;
            } else {
                std::cout << "Blocking INBOUND traffic..." << std::endl;
                if (ctrl.blockInbound(target)) {
                    std::cout << "✓ INBOUND BLOCKED! (Process can't receive data)\n" << std::endl;
                } else {
                    std::cout << "✗ Failed! Is the process running?\n" << std::endl;
                }
            }
        }
        else if (cmd == "block" || cmd == "b") {
            if (ctrl.isBlockedOutbound() && ctrl.isBlockedInbound()) {
                std::cout << "Already blocked both directions!" << std::endl;
            } else {
                std::cout << "Blocking BOTH directions..." << std::endl;
                if (ctrl.block(target)) {
                    std::cout << "✓ FULLY BLOCKED! (No network access)\n" << std::endl;
                } else {
                    std::cout << "✗ Failed! Is the process running?\n" << std::endl;
                }
            }
        }
        else if (cmd == "unblock" || cmd == "u") {
            if (!ctrl.isBlocked()) {
                std::cout << "Already unblocked!" << std::endl;
            } else {
                std::cout << "Unblocking..." << std::endl;
                ctrl.unblock();
                std::cout << "✓ UNBLOCKED! (Network restored)\n" << std::endl;
            }
        }
        else if (cmd == "status" || cmd == "s") {
            std::cout << "\n━━━━━━━━━━━━━━━━━━━━━━━━━━" << std::endl;
            std::cout << "Target:   " << target << std::endl;
            std::cout << "Outbound: " << (ctrl.isBlockedOutbound() ? "BLOCKED ⬆" : "OPEN") << std::endl;
            std::cout << "Inbound:  " << (ctrl.isBlockedInbound() ? "BLOCKED ⬇" : "OPEN") << std::endl;
            std::cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━\n" << std::endl;
        }
        else if (cmd == "quit" || cmd == "q" || cmd == "exit") {
            break;
        }
        else {
            std::cout << "Unknown command. Type 'block', 'unblock', or 'quit'\n" << std::endl;
        }
    }
    
    ctrl.unblock();
    std::cout << "\nGoodbye!" << std::endl;
    return 0;
}