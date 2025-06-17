#include "../headers/kdmapper_manager.h"
#include <iostream>
#include <fstream>
#include <shlobj.h>
#include <urlmon.h>
#include <filesystem>
#include <shlwapi.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shlwapi.lib")

KdMapperManager::KdMapperManager()
    : is_mapped(false)
{
    temp_directory = GetTempDirectory();
    kdmapper_path = temp_directory + "\\kdmapper.exe";
    driver_path = "";
}

KdMapperManager::~KdMapperManager()
{
    if (is_mapped)
    {
        UnmapDriver();
    }
}

bool KdMapperManager::DownloadKdMapper()
{
    LogMessage("Downloading kdmapper...");
    
    // kdmapper GitHub release URL
    std::string kdmapper_url = "https://github.com/TheCruZ/kdmapper/releases/latest/download/kdmapper.exe";
    
    // Check if kdmapper already exists
    if (FileExists(kdmapper_path))
    {
        LogMessage("kdmapper already exists, skipping download");
        return true;
    }

    // Create temp directory if it doesn't exist
    std::filesystem::create_directories(temp_directory);

    // Download kdmapper
    if (!DownloadFile(kdmapper_url, kdmapper_path))
    {
        LogMessage("Failed to download kdmapper from GitHub");
        
        // Try alternative download method or bundled version
        LogMessage("Trying alternative download source...");
        
        // Alternative URL (backup mirror)
        std::string alt_url = "https://github.com/TheCruZ/kdmapper/releases/download/v1.0/kdmapper.exe";
        if (!DownloadFile(alt_url, kdmapper_path))
        {
            LogMessage("Failed to download kdmapper from alternative source");
            return false;
        }
    }

    LogMessage("kdmapper downloaded successfully");
    return true;
}

bool KdMapperManager::MapDriver(const std::string& sys_file_path)
{
    if (!FileExists(sys_file_path))
    {
        LogMessage("Driver file not found: " + sys_file_path);
        return false;
    }

    if (!FileExists(kdmapper_path))
    {
        LogMessage("kdmapper not found, downloading...");
        if (!DownloadKdMapper())
        {
            LogMessage("Failed to download kdmapper");
            return false;
        }
    }

    driver_path = sys_file_path;
    
    LogMessage("Mapping driver with kdmapper...");
    LogMessage("Driver: " + driver_path);
    LogMessage("kdmapper: " + kdmapper_path);

    if (!ExecuteKdMapper())
    {
        LogMessage("Failed to execute kdmapper");
        return false;
    }

    is_mapped = true;
    LogMessage("Driver mapped successfully!");
    return true;
}

bool KdMapperManager::UnmapDriver()
{
    if (!is_mapped)
    {
        return true;
    }

    LogMessage("Unmapping driver...");
    
    // kdmapper doesn't have an unmap feature, but we can track the state
    is_mapped = false;
    LogMessage("Driver unmapped (tracked state)");
    
    return true;
}

void KdMapperManager::SetLogCallback(std::function<void(const std::string&)> callback)
{
    log_callback = callback;
}

std::string KdMapperManager::GetTempDirectory()
{
    char temp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_path);
    return std::string(temp_path) + "AdvancedDebugManager";
}

bool KdMapperManager::FileExists(const std::string& path)
{
    return PathFileExistsA(path.c_str()) != FALSE;
}

bool KdMapperManager::DownloadFile(const std::string& url, const std::string& local_path)
{
    // Convert strings to wide strings for URLDownloadToFile
    int url_len = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
    int path_len = MultiByteToWideChar(CP_UTF8, 0, local_path.c_str(), -1, nullptr, 0);
    
    std::wstring wide_url(url_len, L'\0');
    std::wstring wide_path(path_len, L'\0');
    
    MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, &wide_url[0], url_len);
    MultiByteToWideChar(CP_UTF8, 0, local_path.c_str(), -1, &wide_path[0], path_len);

    HRESULT hr = URLDownloadToFileW(nullptr, wide_url.c_str(), wide_path.c_str(), 0, nullptr);
    return SUCCEEDED(hr);
}

bool KdMapperManager::ExtractZip(const std::string& zip_path, const std::string& extract_path)
{
    // Simple zip extraction - would need additional library for full implementation
    // For now, assume kdmapper is downloaded as standalone executable
    return true;
}

bool KdMapperManager::FindDriverFile()
{
    // Search for .sys files in common locations
    std::vector<std::string> search_paths = {
        "x64\\Debug\\kernel_mode.sys",
        "x64\\Release\\kernel_mode.sys",
        "kernel_mode\\x64\\Debug\\kernel_mode.sys",
        "kernel_mode\\x64\\Release\\kernel_mode.sys",
        "kernel_mode.sys"
    };

    for (const auto& path : search_paths)
    {
        if (FileExists(path))
        {
            driver_path = std::filesystem::absolute(path).string();
            return true;
        }
    }

    return false;
}

bool KdMapperManager::ExecuteKdMapper()
{
    // Build command line
    std::string cmd_line = "\"" + kdmapper_path + "\" \"" + driver_path + "\"";
    
    LogMessage("Executing: " + cmd_line);

    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Hide kdmapper window

    // Execute kdmapper
    if (!CreateProcessA(nullptr, &cmd_line[0], nullptr, nullptr, FALSE, 
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        LogMessage("Failed to create kdmapper process");
        return false;
    }

    // Wait for kdmapper to complete
    LogMessage("Waiting for kdmapper to complete...");
    DWORD wait_result = WaitForSingleObject(pi.hProcess, 30000); // 30 second timeout

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (wait_result == WAIT_TIMEOUT)
    {
        LogMessage("kdmapper timed out");
        return false;
    }

    if (exit_code != 0)
    {
        LogMessage("kdmapper failed with exit code: " + std::to_string(exit_code));
        return false;
    }

    LogMessage("kdmapper completed successfully");
    return true;
}

void KdMapperManager::LogMessage(const std::string& message)
{
    if (log_callback)
    {
        log_callback("[kdmapper] " + message);
    }
}
