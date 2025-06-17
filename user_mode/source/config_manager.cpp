#include "../headers/config_manager.h"
#include <fstream>
#include <sstream>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")

ConfigManager::ConfigManager()
{
    config_file_path = GetConfigFilePath();
    SetDefaults();
}

ConfigManager::~ConfigManager()
{
    SaveConfig();
}

bool ConfigManager::LoadConfig()
{
    std::ifstream config_file(config_file_path);
    if (!config_file.is_open())
    {
        // Create default config if file doesn't exist
        SetDefaults();
        return SaveConfig();
    }

    std::string line;
    while (std::getline(config_file, line))
    {
        if (line.empty() || line[0] == '#')
            continue;

        size_t pos = line.find('=');
        if (pos == std::string::npos)
            continue;

        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);

        if (key == "x64dbg_path")
        {
            x64dbg_path = value;
        }
        else if (key == "default_proxy_port")
        {
            default_proxy_port = std::stoi(value);
        }
        else if (key == "default_target_host")
        {
            default_target_host = value;
        }
        else if (key == "default_target_port")
        {
            default_target_port = std::stoi(value);
        }
        else if (key == "auto_hide_debugger")
        {
            auto_hide_debugger = (value == "true" || value == "1");
        }
        else if (key == "enable_anti_anti_debug")
        {
            enable_anti_anti_debug = (value == "true" || value == "1");
        }
        else if (key == "log_packets")
        {
            log_packets = (value == "true" || value == "1");
        }
    }

    config_file.close();
    return true;
}

bool ConfigManager::SaveConfig()
{
    std::ofstream config_file(config_file_path);
    if (!config_file.is_open())
    {
        return false;
    }

    config_file << "# Advanced Debug Manager Configuration\n";
    config_file << "# Auto-generated config file\n\n";
    
    config_file << "x64dbg_path=" << x64dbg_path << "\n";
    config_file << "default_proxy_port=" << default_proxy_port << "\n";
    config_file << "default_target_host=" << default_target_host << "\n";
    config_file << "default_target_port=" << default_target_port << "\n";
    config_file << "auto_hide_debugger=" << (auto_hide_debugger ? "true" : "false") << "\n";
    config_file << "enable_anti_anti_debug=" << (enable_anti_anti_debug ? "true" : "false") << "\n";
    config_file << "log_packets=" << (log_packets ? "true" : "false") << "\n";

    config_file.close();
    return true;
}

std::string ConfigManager::GetConfigFilePath()
{
    char path[MAX_PATH];
    if (SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path) == S_OK)
    {
        std::string config_dir = std::string(path) + "\\AdvancedDebugManager";
        CreateDirectoryA(config_dir.c_str(), nullptr);
        return config_dir + "\\config.ini";
    }
    
    return "config.ini"; // Fallback to current directory
}

void ConfigManager::SetDefaults()
{
    x64dbg_path = "C:\\Program Files\\x64dbg\\x64dbg.exe";
    default_proxy_port = 8080;
    default_target_host = "127.0.0.1";
    default_target_port = 80;
    auto_hide_debugger = true;
    enable_anti_anti_debug = true;
    log_packets = true;
}
