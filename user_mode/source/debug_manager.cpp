#include "../headers/debug_manager.h"
#include <iostream>
#include <shlwapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "shlwapi.lib")

DebugManager::DebugManager()
    : target_process(nullptr), target_pid(0), is_debugging(false)
{
    ZeroMemory(&x64dbg_process, sizeof(x64dbg_process));
}

DebugManager::~DebugManager()
{
    StopDebugging();
}

bool DebugManager::SetX64DbgPath(const std::string& path)
{
    if (!PathFileExistsA(path.c_str()))
    {
        return false;
    }
    
    x64dbg_path = path;
    return true;
}

bool DebugManager::AttachToProcess(DWORD pid)
{
    target_pid = pid;
    target_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    if (!target_process)
    {
        return false;
    }

    return true;
}

bool DebugManager::LaunchProcessForDebugging(const std::string& exe_path)
{
    if (!PathFileExistsA(exe_path.c_str()))
    {
        return false;
    }

    // Create process in suspended state
    STARTUPINFOA si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);

    std::string cmdline = "\"" + exe_path + "\"";
    
    if (!CreateProcessA(nullptr, &cmdline[0], nullptr, nullptr, FALSE, 
                       CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
    {
        return false;
    }

    target_pid = pi.dwProcessId;
    target_process = pi.hProcess;
    
    // Launch x64dbg and attach to this process
    if (!LaunchX64Dbg(exe_path))
    {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Resume the suspended process
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    return true;
}

bool DebugManager::HideDebugger()
{
    if (!x64dbg_process.hProcess)
    {
        return false;
    }

    // Hide x64dbg process from task manager and other enumeration methods
    return HideProcessFromTasks(x64dbg_process.dwProcessId);
}

bool DebugManager::StartDebugging()
{
    if (is_debugging || !target_process)
    {
        return false;
    }

    if (!LaunchX64Dbg())
    {
        return false;
    }

    is_debugging = true;
    return true;
}

void DebugManager::StopDebugging()
{
    if (x64dbg_process.hProcess)
    {
        TerminateProcess(x64dbg_process.hProcess, 0);
        CloseHandle(x64dbg_process.hProcess);
        CloseHandle(x64dbg_process.hThread);
        ZeroMemory(&x64dbg_process, sizeof(x64dbg_process));
    }

    if (target_process)
    {
        CloseHandle(target_process);
        target_process = nullptr;
    }

    target_pid = 0;
    is_debugging = false;
}

bool DebugManager::LaunchX64Dbg(const std::string& target_exe)
{
    if (x64dbg_path.empty())
    {
        return false;
    }

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Start hidden

    std::string cmdline = "\"" + x64dbg_path + "\"";
    
    if (!target_exe.empty())
    {
        cmdline += " \"" + target_exe + "\"";
    }
    else if (target_pid != 0)
    {
        cmdline += " -p " + std::to_string(target_pid);
    }

    if (!CreateProcessA(nullptr, &cmdline[0], nullptr, nullptr, FALSE, 
                       0, nullptr, nullptr, &si, &x64dbg_process))
    {
        return false;
    }

    // Give x64dbg time to start
    Sleep(2000);

    return true;
}

bool DebugManager::HideProcessFromTasks(DWORD pid)
{
    // This would typically involve more advanced techniques like:
    // - Unhooking from PEB
    // - Hiding from process enumeration
    // - Using kernel driver to hide process
    
    // For now, just return true as this requires kernel-level implementation
    return true;
}
