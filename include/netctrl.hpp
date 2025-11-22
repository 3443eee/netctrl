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
#include <set>
#include <atomic>
#include <cstdio>
#include <cstdlib>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
    #pragma comment(lib, "advapi32.lib")
#else
    #include <unistd.h>
#endif

namespace netctrl {

class NetCtrl {
public:
    NetCtrl(const std::string& rule_name = "netctrl") : rule_name_(rule_name) {
        init();
    }

    ~NetCtrl() {
        unblock();
    }

    // Main blocking functions
    bool blockOutbound(const std::string& process_name) {
        return blockDirection(process_name, false);
    }

    bool blockInbound(const std::string& process_name) {
        return blockDirection(process_name, true);
    }

    bool block(const std::string& process_name) {
        // Block both directions (like calling both functions)
        bool out = blockOutbound(process_name);
        bool in = blockInbound(process_name);
        return out && in;
    }

    bool unblock() {
        if (!is_blocked_outbound_ && !is_blocked_inbound_) return true;
        
#ifdef _WIN32
        return unblockWindows();
#else
        return unblockLinux();
#endif
    }

    bool isBlocked() const { return is_blocked_outbound_ || is_blocked_inbound_; }
    bool isBlockedOutbound() const { return is_blocked_outbound_; }
    bool isBlockedInbound() const { return is_blocked_inbound_; }

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
    std::string rule_name_;
    std::string process_name_;
    std::string exe_path_;
    std::set<int> blocked_pids_out_;
    std::set<int> blocked_pids_in_;
    std::string blocked_cgroup_;
    bool is_blocked_outbound_ = false;
    bool is_blocked_inbound_ = false;

    void init() {
#ifndef _WIN32
        // Create iptables chains once at startup (async to avoid blocking)
        static std::atomic<bool> setup{false};
        if (!setup.exchange(true)) {
            system("(iptables -w -N NETCTRL_OUT 2>/dev/null; "
                   "iptables -w -N NETCTRL_IN 2>/dev/null; "
                   "iptables -w -C OUTPUT -j NETCTRL_OUT 2>/dev/null || "
                   "iptables -w -I OUTPUT -j NETCTRL_OUT; "
                   "iptables -w -C INPUT -j NETCTRL_IN 2>/dev/null || "
                   "iptables -w -I INPUT -j NETCTRL_IN) >/dev/null 2>&1 &");
        }
#endif
    }

    bool blockDirection(const std::string& proc_name, bool inbound) {
#ifdef _WIN32
        return blockWindows(proc_name, inbound);
#else
        return blockLinux(proc_name, inbound);
#endif
    }

#ifdef _WIN32
    bool blockWindows(const std::string& proc_name, bool inbound) {
        // Find process and get exe path (only once)
        if (exe_path_.empty()) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE) return false;

            PROCESSENTRY32W entry;
            entry.dwSize = sizeof(entry);

            bool found = false;
            if (Process32FirstW(snap, &entry)) {
                do {
                    std::wstring wname(entry.szExeFile);
                    std::string name(wname.begin(), wname.end());
                    if (name.find(proc_name) != std::string::npos) {
                        HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
                        if (proc) {
                            char path[MAX_PATH];
                            DWORD size = MAX_PATH;
                            if (QueryFullProcessImageNameA(proc, 0, path, &size)) {
                                exe_path_ = path;
                                found = true;
                            }
                            CloseHandle(proc);
                            if (found) break;
                        }
                    }
                } while (Process32NextW(snap, &entry));
            }
            CloseHandle(snap);

            if (!found) return false;
            process_name_ = proc_name;
        }

        // Add firewall rule
        std::string dir = inbound ? "in" : "out";
        std::string suffix = inbound ? "_in" : "_out";
        std::string cmd = "netsh advfirewall firewall add rule name=\"" + rule_name_ + suffix +
                         "\" dir=" + dir + " action=block program=\"" + exe_path_ + "\" >nul 2>&1";
        
        if (system(cmd.c_str()) == 0) {
            if (inbound) is_blocked_inbound_ = true;
            else is_blocked_outbound_ = true;
            return true;
        }
        return false;
    }

    bool unblockWindows() {
        system(("netsh advfirewall firewall delete rule name=\"" + rule_name_ + "_out\" >nul 2>&1").c_str());
        system(("netsh advfirewall firewall delete rule name=\"" + rule_name_ + "_in\" >nul 2>&1").c_str());
        is_blocked_outbound_ = false;
        is_blocked_inbound_ = false;
        exe_path_.clear();
        return true;
    }
#else
    bool blockLinux(const std::string& proc_name, bool inbound) {
        // Use pgrep for speed
        std::string cmd = "pgrep -x '" + proc_name + "'";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) return false;

        char buf[32];
        bool found = false;
        
        // Get first PID
        if (fgets(buf, sizeof(buf), pipe)) {
            int pid = atoi(buf);
            if (pid > 0) {
                // Check if flatpak (only once if not already checked)
                if (blocked_cgroup_.empty() && process_name_.empty()) {
                    std::string cgroup_file = "/proc/" + std::to_string(pid) + "/cgroup";
                    FILE* f = fopen(cgroup_file.c_str(), "r");
                    if (f) {
                        char line[512];
                        if (fgets(line, sizeof(line), f)) {
                            std::string cgline(line);
                            if (cgline.find("flatpak") != std::string::npos || 
                                cgline.find("app-") != std::string::npos) {
                                size_t pos = cgline.find_last_of(':');
                                if (pos != std::string::npos) {
                                    blocked_cgroup_ = cgline.substr(pos + 1);
                                    blocked_cgroup_.erase(blocked_cgroup_.find_last_not_of(" \n\r\t") + 1);
                                }
                            }
                        }
                        fclose(f);
                    }
                    process_name_ = proc_name;
                }

                // Block by cgroup if flatpak
                if (!blocked_cgroup_.empty()) {
                    std::string chain = inbound ? "NETCTRL_IN" : "NETCTRL_OUT";
                    std::string block_cmd = "iptables -w -A " + chain + " -m cgroup --path \"" + 
                                           blocked_cgroup_ + "\" -j DROP 2>/dev/null";
                    if (system(block_cmd.c_str()) == 0) {
                        found = true;
                    }
                }
                // Fallback: block by PID
                else {
                    std::string chain = inbound ? "NETCTRL_IN" : "NETCTRL_OUT";
                    std::string block_cmd = "iptables -w -A " + chain + " -m owner --pid-owner " + 
                                           std::to_string(pid) + " -j DROP 2>/dev/null";
                    if (system(block_cmd.c_str()) == 0) {
                        if (inbound) blocked_pids_in_.insert(pid);
                        else blocked_pids_out_.insert(pid);
                        found = true;
                    }
                }
            }
        }
        pclose(pipe);

        if (found) {
            if (inbound) is_blocked_inbound_ = true;
            else is_blocked_outbound_ = true;
        }
        return found;
    }

    bool unblockLinux() {
        // Unblock cgroup rules
        if (!blocked_cgroup_.empty()) {
            system(("iptables -w -D NETCTRL_OUT -m cgroup --path \"" + 
                   blocked_cgroup_ + "\" -j DROP 2>/dev/null").c_str());
            system(("iptables -w -D NETCTRL_IN -m cgroup --path \"" + 
                   blocked_cgroup_ + "\" -j DROP 2>/dev/null").c_str());
            blocked_cgroup_.clear();
        }

        // Unblock PID rules
        for (int pid : blocked_pids_out_) {
            system(("iptables -w -D NETCTRL_OUT -m owner --pid-owner " + 
                   std::to_string(pid) + " -j DROP 2>/dev/null").c_str());
        }
        for (int pid : blocked_pids_in_) {
            system(("iptables -w -D NETCTRL_IN -m owner --pid-owner " + 
                   std::to_string(pid) + " -j DROP 2>/dev/null").c_str());
        }
        blocked_pids_out_.clear();
        blocked_pids_in_.clear();

        is_blocked_outbound_ = false;
        is_blocked_inbound_ = false;
        process_name_.clear();
        return true;
    }
#endif
};

} // namespace netctrl

#endif // NETCTRL_HPP
