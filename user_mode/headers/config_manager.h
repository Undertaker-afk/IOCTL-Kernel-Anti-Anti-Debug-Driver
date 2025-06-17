#pragma once

#include <string>
#include <windows.h>

class ConfigManager
{
private:
    std::string config_file_path;
    std::string x64dbg_path;
    int default_proxy_port;
    std::string default_target_host;
    int default_target_port;
    bool auto_hide_debugger;
    bool enable_anti_anti_debug;
    bool log_packets;

public:
    ConfigManager();
    ~ConfigManager();

    bool LoadConfig();
    bool SaveConfig();

    // Getters
    const std::string& GetX64DbgPath() const { return x64dbg_path; }
    int GetDefaultProxyPort() const { return default_proxy_port; }
    const std::string& GetDefaultTargetHost() const { return default_target_host; }
    int GetDefaultTargetPort() const { return default_target_port; }
    bool GetAutoHideDebugger() const { return auto_hide_debugger; }
    bool GetEnableAntiAntiDebug() const { return enable_anti_anti_debug; }
    bool GetLogPackets() const { return log_packets; }

    // Setters
    void SetX64DbgPath(const std::string& path) { x64dbg_path = path; }
    void SetDefaultProxyPort(int port) { default_proxy_port = port; }
    void SetDefaultTargetHost(const std::string& host) { default_target_host = host; }
    void SetDefaultTargetPort(int port) { default_target_port = port; }
    void SetAutoHideDebugger(bool enable) { auto_hide_debugger = enable; }
    void SetEnableAntiAntiDebug(bool enable) { enable_anti_anti_debug = enable; }
    void SetLogPackets(bool enable) { log_packets = enable; }

private:
    std::string GetConfigFilePath();
    void SetDefaults();
};
