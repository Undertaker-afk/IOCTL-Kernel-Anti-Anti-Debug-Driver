#pragma once

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include "../headers/debug_manager.h"
#include "../headers/mitm_proxy.h"
#include "../headers/driver_helper.h"

#pragma comment(lib, "comctl32.lib")

class GuiManager
{
private:
    HWND main_window;
    HWND process_listbox;
    HWND log_edit;
    HWND start_debug_btn;
    HWND stop_debug_btn;
    HWND launch_exe_btn;
    HWND proxy_port_edit;
    HWND target_host_edit;
    HWND target_port_edit;
    HWND start_proxy_btn;
    HWND stop_proxy_btn;
    HWND packet_listbox;
    
    std::unique_ptr<DebugManager> debug_manager;
    std::unique_ptr<MitmProxy> mitm_proxy;
    std::unique_ptr<ioctl::Driver> driver;
    
    struct ProcessInfo
    {
        DWORD pid;
        std::string name;
        std::string path;
    };
    
    std::vector<ProcessInfo> processes;

public:
    GuiManager();
    ~GuiManager();

    bool Initialize();
    void Run();
    void Shutdown();

private:
    bool CreateMainWindow();
    bool CreateControls();
    void RefreshProcessList();
    void LogMessage(const std::string& message);
    void OnProcessSelected();
    void OnStartDebugging();
    void OnStopDebugging();
    void OnLaunchExe();
    void OnStartProxy();
    void OnStopProxy();
    void OnPacketReceived(const NetworkPacket& packet);
    
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static std::vector<ProcessInfo> EnumerateProcesses();
};
