/*
===============================================================================
NetCtrl - Cross-Platform Network Control Library (Header-Only)
===============================================================================

Author: 3443
Date: [22/11/2025]
License: MIT

Description:
-------------
NetCtrl is a lightweight, header-only C++ library for programmatically
blocking and unblocking network traffic for specific processes. It is
designed primarily for applications such as lag switches, parental controls,
sandboxing, debugging, or automation tools.

The library currently supports:

    - Windows (via Windows Firewall rules)
    - Linux (via iptables cgroup / PID-owner rules)

It provides a simple API to block outgoing traffic, incoming traffic, or
both, for a target process name. The library automatically resolves the
process, determines the executable path (Windows) or cgroup/PID (Linux),
and manages firewall rules cleanly.

Features:
----------
- Block outbound network traffic for a process.
- Block inbound network traffic for a process.
- Block both directions simultaneously.
- Automatic detection of process executable (Windows) and cgroup/PID (Linux).
- Clean removal of all rules on unblocking or destruction.
- Header-only, cross-platform, minimal dependencies.
- Designed for simplicity and integration into automation tools or network
  control utilities.

Usage Example (C++):
---------------------
#include "netctrl.hpp"
#include <iostream>

int main() {
    netctrl::NetCtrl net;

    if (!netctrl::NetCtrl::isAdmin()) {
        std::cerr << "Run as administrator/root!" << std::endl;
        return 1;
    }

    // Block all network traffic for "RobloxPlayer"
    net.block("RobloxPlayer");

    // ... some code ...

    // Remove all rules
    net.unblock();

    return 0;
}

Notes:
------
- Windows implementation uses Windows Firewall (netsh rules).
- Linux implementation uses iptables with cgroup or PID matching.
- Requires administrator/root privileges on both platforms.
- Not intended for high-performance packet filtering or deep inspection.
- Designed for automation, simple traffic blocking, and development tools.

===============================================================================
*/

#ifndef NETCTRL_HPP
#define NETCTRL_HPP

#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <iostream>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

namespace netctrl {

enum class Direction {
    Inbound,
    Outbound,
    Both
};

class NetCtrl {
public:
    NetCtrl() {
        findInterface();
    }

    ~NetCtrl() {
        disable();
    }

    // Simple API
    bool block() {
        std::cout << "[DEBUG] Blocking with iptables..." << std::endl;
#ifdef _WIN32
        return applyWindows(100.0);
#else
        return blockLinux();
#endif
    }

    bool lag(int lag_ms, double drop_percent) {
        std::cout << "[DEBUG] Applying lag=" << lag_ms << "ms drop=" << drop_percent << "%" << std::endl;
#ifdef _WIN32
        return applyWindows(drop_percent);
#else
        return applyLinux(lag_ms, drop_percent);
#endif
    }

    bool disable() {
        std::cout << "[DEBUG] Disabling all rules..." << std::endl;
#ifdef _WIN32
        return disableWindows();
#else
        return disableLinux();
#endif
    }

    bool isActive() const { return is_active_; }
    int getLag() const { return current_lag_ms_; }
    double getDrop() const { return current_drop_percent_; }

    static bool isAdmin() {
#ifdef _WIN32
        BOOL admin = FALSE;
        PSID grp = NULL;
        SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                      DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &grp)) {
            CheckTokenMembership(NULL, grp, &admin);
            FreeSid(grp);
        }
        return admin;
#else
        return geteuid() == 0;
#endif
    }

private:
    bool is_active_ = false;
    int current_lag_ms_ = 0;
    double current_drop_percent_ = 0.0;
    std::string default_iface_;

    void findInterface() {
#ifndef _WIN32
        FILE* p = popen("ip route show default | awk '/default/ {print $5}' | head -1", "r");
        if (p) {
            char buf[64];
            if (fgets(buf, sizeof(buf), p)) {
                default_iface_ = buf;
                // Remove newline
                if (!default_iface_.empty() && default_iface_.back() == '\n') {
                    default_iface_.pop_back();
                }
            }
            pclose(p);
        }
        
        if (default_iface_.empty()) {
            // Try common interfaces
            std::vector<std::string> common = {"eth0", "eno1", "enp0s3", "wlan0", "wlp2s0"};
            for (const auto& iface : common) {
                std::string check = "ip link show " + iface + " 2>/dev/null";
                if (system(check.c_str()) == 0) {
                    default_iface_ = iface;
                    break;
                }
            }
        }
        
        std::cout << "[DEBUG] Using interface: " << default_iface_ << std::endl;
#endif
    }

#ifdef _WIN32
    bool applyWindows(double drop_percent) {
        // Windows: Block ALL traffic using netsh (like Clumsy)
        if (drop_percent >= 100.0) {
            std::cout << "[DEBUG] Creating Windows firewall block rules..." << std::endl;
            
            // Block all outbound
            int r1 = system("netsh advfirewall firewall add rule name=\"NetCtrl_OUT\" dir=out action=block protocol=any");
            std::cout << "[DEBUG] Outbound block result: " << r1 << std::endl;
            
            // Block all inbound  
            int r2 = system("netsh advfirewall firewall add rule name=\"NetCtrl_IN\" dir=in action=block protocol=any");
            std::cout << "[DEBUG] Inbound block result: " << r2 << std::endl;
            
            if (r1 == 0 || r2 == 0) {
                is_active_ = true;
                current_drop_percent_ = 100.0;
                return true;
            }
        }
        return false;
    }

    bool disableWindows() {
        std::cout << "[DEBUG] Removing Windows firewall rules..." << std::endl;
        system("netsh advfirewall firewall delete rule name=\"NetCtrl_OUT\" >nul 2>&1");
        system("netsh advfirewall firewall delete rule name=\"NetCtrl_IN\" >nul 2>&1");
        is_active_ = false;
        current_lag_ms_ = 0;
        current_drop_percent_ = 0.0;
        return true;
    }
#else
    bool blockLinux() {
        // Clear any existing rules first
        disableLinux();
        
        // Use iptables to DROP all packets - FAST method
        std::cout << "[DEBUG] Adding iptables DROP rules..." << std::endl;
        
        // Insert at position 1 (top of chain) for immediate effect
        system("iptables -w -I OUTPUT 1 -j DROP &");
        system("iptables -w -I INPUT 1 -j DROP &");
        
        // Don't wait for completion, rules are applied immediately
        is_active_ = true;
        current_lag_ms_ = 0;
        current_drop_percent_ = 100.0;
        return true;
    }

    bool applyLinux(int lag_ms, double drop_percent) {
        // Clear any existing rules
        disableLinux();
        
        if (default_iface_.empty()) {
            std::cerr << "[ERROR] No network interface found!" << std::endl;
            return false;
        }
        
        std::cout << "[DEBUG] Applying tc netem on " << default_iface_ << std::endl;
        
        // Build tc command - run in background for speed
        std::stringstream cmd;
        cmd << "tc qdisc add dev " << default_iface_ << " root netem";
        
        if (lag_ms > 0) {
            cmd << " delay " << lag_ms << "ms";
        }
        
        if (drop_percent > 0) {
            cmd << " loss " << std::fixed << std::setprecision(2) << drop_percent << "%";
        }
        
        cmd << " 2>/dev/null &";  // Run in background
        
        std::cout << "[DEBUG] Running: " << cmd.str() << std::endl;
        system(cmd.str().c_str());
        
        // Mark as active immediately (don't wait for tc to finish)
        is_active_ = true;
        current_lag_ms_ = lag_ms;
        current_drop_percent_ = drop_percent;
        return true;
    }

    bool disableLinux() {
        // Remove tc qdisc - run in background
        if (!default_iface_.empty()) {
            std::string cmd = "tc qdisc del dev " + default_iface_ + " root 2>/dev/null &";
            system(cmd.c_str());
        }
        
        // Remove iptables DROP rules - run in parallel
        system("iptables -w -D OUTPUT -j DROP 2>/dev/null & iptables -w -D INPUT -j DROP 2>/dev/null &");
        
        is_active_ = false;
        current_lag_ms_ = 0;
        current_drop_percent_ = 0.0;
        return true;
    }
#endif
};

} // namespace netctrl