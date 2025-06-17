#pragma once

#include <windows.h>
#include <string>
#include <functional>

class KdMapperManager
{
private:
    std::string kdmapper_path;
    std::string driver_path;
    std::string temp_directory;
    bool is_mapped;
    std::function<void(const std::string&)> log_callback;

public:
    KdMapperManager();
    ~KdMapperManager();

    bool DownloadKdMapper();
    bool MapDriver(const std::string& sys_file_path);
    bool UnmapDriver();
    bool IsDriverMapped() const { return is_mapped; }
    
    void SetLogCallback(std::function<void(const std::string&)> callback);
    
    // Utility functions
    static std::string GetTempDirectory();
    static bool FileExists(const std::string& path);
    static bool DownloadFile(const std::string& url, const std::string& local_path);
    static bool ExtractZip(const std::string& zip_path, const std::string& extract_path);

private:
    bool FindDriverFile();
    bool ExecuteKdMapper();
    void LogMessage(const std::string& message);
};
