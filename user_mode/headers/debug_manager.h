#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <thread>

class DebugManager
{
private:
    std::string x64dbg_path;
    PROCESS_INFORMATION x64dbg_process;
    HANDLE target_process;
    DWORD target_pid;
    bool is_debugging;

public:
    DebugManager();
    ~DebugManager();

    bool SetX64DbgPath(const std::string& path);
    bool AttachToProcess(DWORD pid);
    bool LaunchProcessForDebugging(const std::string& exe_path);
    bool HideDebugger();
    bool StartDebugging();
    void StopDebugging();
    bool IsDebugging() const { return is_debugging; }
    
private:
    bool LaunchX64Dbg(const std::string& target_exe = "");
    bool HideProcessFromTasks(DWORD pid);
};
