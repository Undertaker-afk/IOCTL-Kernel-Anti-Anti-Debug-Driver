#include "../headers/gui_manager.h"
#include <commctrl.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <sstream>
#include <iomanip>

#define ID_PROCESS_LISTBOX 1001
#define ID_LOG_EDIT 1002
#define ID_START_DEBUG_BTN 1003
#define ID_STOP_DEBUG_BTN 1004
#define ID_LAUNCH_EXE_BTN 1005
#define ID_PROXY_PORT_EDIT 1006
#define ID_TARGET_HOST_EDIT 1007
#define ID_TARGET_PORT_EDIT 1008
#define ID_START_PROXY_BTN 1009
#define ID_STOP_PROXY_BTN 1010
#define ID_PACKET_LISTBOX 1011
#define ID_REFRESH_BTN 1012

GuiManager::GuiManager()
    : main_window(nullptr)
{
    debug_manager = std::make_unique<DebugManager>();
    mitm_proxy = std::make_unique<MitmProxy>();
    driver = std::make_unique<ioctl::Driver>();
    kdmapper_manager = std::make_unique<KdMapperManager>();
}

GuiManager::~GuiManager()
{
    Shutdown();
}

bool GuiManager::Initialize()
{
    InitCommonControls();

    if (!CreateMainWindow())
    {
        return false;
    }

    if (!CreateControls())
    {
        return false;
    }

    // Set default x64dbg path (user should configure this)
    debug_manager->SetX64DbgPath("C:\\Program Files\\x64dbg\\x64dbg.exe");

    // Setup MITM proxy callback
    mitm_proxy->SetPacketCallback([this](const NetworkPacket& packet) {
        OnPacketReceived(packet);
    });

    // Setup kdmapper logging
    kdmapper_manager->SetLogCallback([this](const std::string& message) {
        LogMessage(message);
    });

    RefreshProcessList();
    LogMessage("Application initialized successfully");

    return true;
}

bool GuiManager::InitializeKdMapper()
{
    LogMessage("=== Initializing kdmapper and driver mapping ===");
    
    // Step 1: Download kdmapper if needed
    if (!kdmapper_manager->DownloadKdMapper())
    {
        LogMessage("ERROR: Failed to download kdmapper!");
        MessageBoxA(main_window, 
                   "Failed to download kdmapper!\n"
                   "Please check your internet connection or download manually.",
                   "kdmapper Error", 
                   MB_OK | MB_ICONERROR);
        return false;
    }

    LogMessage("kdmapper ready");

    // Step 2: Find driver file
    std::vector<std::string> driver_search_paths = {
        "x64\\Debug\\kernel_mode.sys",
        "x64\\Release\\kernel_mode.sys", 
        "kernel_mode\\x64\\Debug\\kernel_mode.sys",
        "kernel_mode\\x64\\Release\\kernel_mode.sys",
        "kernel_mode.sys"
    };

    std::string driver_path;
    bool driver_found = false;

    for (const auto& path : driver_search_paths)
    {
        if (KdMapperManager::FileExists(path))
        {
            driver_path = path;
            driver_found = true;
            break;
        }
    }

    if (!driver_found)
    {
        LogMessage("ERROR: Driver file (kernel_mode.sys) not found!");
        
        int result = MessageBoxA(main_window,
                               "Driver file (kernel_mode.sys) not found!\n\n"
                               "Please compile the kernel_mode project first.\n"
                               "Expected locations:\n"
                               "- x64\\Debug\\kernel_mode.sys\n"
                               "- x64\\Release\\kernel_mode.sys\n\n"
                               "Do you want to select the driver file manually?",
                               "Driver Not Found",
                               MB_YESNO | MB_ICONWARNING);

        if (result == IDYES)
        {
            OPENFILENAMEA ofn = {};
            char file_path[MAX_PATH] = {};

            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = main_window;
            ofn.lpstrFile = file_path;
            ofn.nMaxFile = sizeof(file_path);
            ofn.lpstrFilter = "Driver Files\0*.sys\0All Files\0*.*\0";
            ofn.nFilterIndex = 1;
            ofn.lpstrTitle = "Select kernel_mode.sys driver file";
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

            if (GetOpenFileNameA(&ofn))
            {
                driver_path = file_path;
                driver_found = true;
            }
        }

        if (!driver_found)
        {
            return false;
        }
    }

    LogMessage("Driver found: " + driver_path);

    // Step 3: Map driver with kdmapper
    LogMessage("Mapping driver with kdmapper...");
    LogMessage("WARNING: This operation requires administrator privileges!");

    if (!kdmapper_manager->MapDriver(driver_path))
    {
        LogMessage("ERROR: Failed to map driver!");
        MessageBoxA(main_window,
                   "Failed to map driver with kdmapper!\n\n"
                   "Possible causes:\n"
                   "- Administrator privileges required\n"
                   "- Antivirus blocking kdmapper\n"
                   "- Driver signing issues\n"
                   "- Windows Defender or HVCI enabled\n\n"
                   "Please run as Administrator and disable real-time protection.",
                   "Driver Mapping Failed",
                   MB_OK | MB_ICONERROR);
        return false;
    }

    LogMessage("Driver mapped successfully!");

    // Step 4: Test driver communication
    LogMessage("Testing driver communication...");
    
    // Give driver time to initialize
    Sleep(2000);

    // Test if we can communicate with the driver
    ioctl::Driver test_driver;
    if (test_driver.driver_handle == INVALID_HANDLE_VALUE)
    {
        LogMessage("WARNING: Cannot communicate with mapped driver!");
        LogMessage("The driver may need additional time to initialize or may have failed to load.");
        
        MessageBoxA(main_window,
                   "Driver mapped but communication test failed!\n\n"
                   "This may be normal - the driver might need more time to initialize.\n"
                   "You can continue and try debugging operations.",
                   "Driver Communication Warning",
                   MB_OK | MB_ICONWARNING);
    }
    else
    {
        LogMessage("Driver communication successful!");
    }

    LogMessage("=== kdmapper initialization complete ===");
    return true;
}

void GuiManager::Run()
{
    ShowWindow(main_window, SW_SHOW);
    UpdateWindow(main_window);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void GuiManager::Shutdown()
{
    if (mitm_proxy)
    {
        mitm_proxy->StopProxy();
    }

    if (debug_manager)
    {
        debug_manager->StopDebugging();
    }

    if (kdmapper_manager && kdmapper_manager->IsDriverMapped())
    {
        LogMessage("Cleaning up mapped driver...");
        kdmapper_manager->UnmapDriver();
    }

    if (main_window)
    {
        DestroyWindow(main_window);
        main_window = nullptr;
    }
}

bool GuiManager::CreateMainWindow()
{
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "DebugManagerApp";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassA(&wc))
    {
        return false;
    }

    main_window = CreateWindowA(
        "DebugManagerApp",
        "Advanced Debug Manager with MITM Proxy",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1200, 800,
        nullptr, nullptr,
        GetModuleHandle(nullptr),
        this
    );

    return main_window != nullptr;
}

bool GuiManager::CreateControls()
{
    // Process selection
    CreateWindowA("STATIC", "Processes:", WS_VISIBLE | WS_CHILD,
                 10, 10, 100, 20, main_window, nullptr, GetModuleHandle(nullptr), nullptr);

    process_listbox = CreateWindowA("LISTBOX", nullptr,
                                   WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL,
                                   10, 35, 300, 200, main_window,
                                   (HMENU)ID_PROCESS_LISTBOX, GetModuleHandle(nullptr), nullptr);

    CreateWindowA("BUTTON", "Refresh", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                 320, 35, 80, 25, main_window, (HMENU)ID_REFRESH_BTN, GetModuleHandle(nullptr), nullptr);

    // Debug controls
    start_debug_btn = CreateWindowA("BUTTON", "Start Debugging", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                   10, 250, 120, 30, main_window, (HMENU)ID_START_DEBUG_BTN, GetModuleHandle(nullptr), nullptr);

    stop_debug_btn = CreateWindowA("BUTTON", "Stop Debugging", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                  140, 250, 120, 30, main_window, (HMENU)ID_STOP_DEBUG_BTN, GetModuleHandle(nullptr), nullptr);

    launch_exe_btn = CreateWindowA("BUTTON", "Launch EXE for Debug", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                  270, 250, 150, 30, main_window, (HMENU)ID_LAUNCH_EXE_BTN, GetModuleHandle(nullptr), nullptr);

    // Proxy controls
    CreateWindowA("STATIC", "MITM Proxy Settings:", WS_VISIBLE | WS_CHILD,
                 450, 10, 150, 20, main_window, nullptr, GetModuleHandle(nullptr), nullptr);

    CreateWindowA("STATIC", "Proxy Port:", WS_VISIBLE | WS_CHILD,
                 450, 35, 80, 20, main_window, nullptr, GetModuleHandle(nullptr), nullptr);

    proxy_port_edit = CreateWindowA("EDIT", "8080", WS_VISIBLE | WS_CHILD | WS_BORDER,
                                   540, 35, 60, 20, main_window, (HMENU)ID_PROXY_PORT_EDIT, GetModuleHandle(nullptr), nullptr);

    CreateWindowA("STATIC", "Target Host:", WS_VISIBLE | WS_CHILD,
                 450, 65, 80, 20, main_window, nullptr, GetModuleHandle(nullptr), nullptr);

    target_host_edit = CreateWindowA("EDIT", "127.0.0.1", WS_VISIBLE | WS_CHILD | WS_BORDER,
                                    540, 65, 100, 20, main_window, (HMENU)ID_TARGET_HOST_EDIT, GetModuleHandle(nullptr), nullptr);

    CreateWindowA("STATIC", "Target Port:", WS_VISIBLE | WS_CHILD,
                 450, 95, 80, 20, main_window, nullptr, GetModuleHandle(nullptr), nullptr);

    target_port_edit = CreateWindowA("EDIT", "80", WS_VISIBLE | WS_CHILD | WS_BORDER,
                                    540, 95, 60, 20, main_window, (HMENU)ID_TARGET_PORT_EDIT, GetModuleHandle(nullptr), nullptr);

    start_proxy_btn = CreateWindowA("BUTTON", "Start Proxy", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                   450, 125, 100, 30, main_window, (HMENU)ID_START_PROXY_BTN, GetModuleHandle(nullptr), nullptr);

    stop_proxy_btn = CreateWindowA("BUTTON", "Stop Proxy", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                                  560, 125, 100, 30, main_window, (HMENU)ID_STOP_PROXY_BTN, GetModuleHandle(nullptr), nullptr);

    // Packet capture
    CreateWindowA("STATIC", "Captured Packets:", WS_VISIBLE | WS_CHILD,
                 450, 170, 120, 20, main_window, nullptr, GetModuleHandle(nullptr), nullptr);

    packet_listbox = CreateWindowA("LISTBOX", nullptr,
                                  WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL,
                                  450, 195, 300, 200, main_window,
                                  (HMENU)ID_PACKET_LISTBOX, GetModuleHandle(nullptr), nullptr);

    // Log window
    CreateWindowA("STATIC", "Log:", WS_VISIBLE | WS_CHILD,
                 10, 300, 50, 20, main_window, nullptr, GetModuleHandle(nullptr), nullptr);

    log_edit = CreateWindowA("EDIT", nullptr,
                            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
                            10, 325, 730, 150, main_window,
                            (HMENU)ID_LOG_EDIT, GetModuleHandle(nullptr), nullptr);

    return true;
}

void GuiManager::RefreshProcessList()
{
    SendMessage(process_listbox, LB_RESETCONTENT, 0, 0);
    processes = EnumerateProcesses();

    for (const auto& proc : processes)
    {
        std::string display_text = proc.name + " (PID: " + std::to_string(proc.pid) + ")";
        SendMessageA(process_listbox, LB_ADDSTRING, 0, (LPARAM)display_text.c_str());
    }
}

void GuiManager::LogMessage(const std::string& message)
{
    SYSTEMTIME st;
    GetLocalTime(&st);

    std::stringstream ss;
    ss << "[" << std::setfill('0') << std::setw(2) << st.wHour
       << ":" << std::setfill('0') << std::setw(2) << st.wMinute
       << ":" << std::setfill('0') << std::setw(2) << st.wSecond
       << "] " << message << "\r\n";

    std::string log_entry = ss.str();

    int text_length = GetWindowTextLengthA(log_edit);
    SendMessageA(log_edit, EM_SETSEL, text_length, text_length);
    SendMessageA(log_edit, EM_REPLACESEL, FALSE, (LPARAM)log_entry.c_str());
}

void GuiManager::OnProcessSelected()
{
    int selection = SendMessage(process_listbox, LB_GETCURSEL, 0, 0);
    if (selection == LB_ERR || selection >= processes.size())
    {
        return;
    }

    const auto& selected_process = processes[selection];
    LogMessage("Selected process: " + selected_process.name + " (PID: " + std::to_string(selected_process.pid) + ")");
}

void GuiManager::OnStartDebugging()
{
    int selection = SendMessage(process_listbox, LB_GETCURSEL, 0, 0);
    if (selection == LB_ERR || selection >= processes.size())
    {
        LogMessage("No process selected");
        return;
    }

    const auto& selected_process = processes[selection];

    // Attach to process using driver
    if (!driver->attach_to_process(selected_process.pid))
    {
        LogMessage("Failed to attach to process via driver");
        return;
    }

    // Enable anti-anti-debug
    driver->enable_anti_anti_debug(selected_process.pid);
    driver->hide_debugger(selected_process.pid);

    // Start debugging with x64dbg
    if (!debug_manager->AttachToProcess(selected_process.pid))
    {
        LogMessage("Failed to attach debug manager to process");
        return;
    }

    if (!debug_manager->StartDebugging())
    {
        LogMessage("Failed to start debugging");
        return;
    }

    // Hide debugger
    debug_manager->HideDebugger();

    LogMessage("Debugging started for process: " + selected_process.name);
}

void GuiManager::OnStopDebugging()
{
    debug_manager->StopDebugging();
    LogMessage("Debugging stopped");
}

void GuiManager::OnLaunchExe()
{
    OPENFILENAMEA ofn = {};
    char file_path[MAX_PATH] = {};

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = main_window;
    ofn.lpstrFile = file_path;
    ofn.nMaxFile = sizeof(file_path);
    ofn.lpstrFilter = "Executable Files\0*.exe\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameA(&ofn))
    {
        if (!debug_manager->LaunchProcessForDebugging(file_path))
        {
            LogMessage("Failed to launch process for debugging: " + std::string(file_path));
            return;
        }

        LogMessage("Launched process for debugging: " + std::string(file_path));
    }
}

void GuiManager::OnStartProxy()
{
    char proxy_port_str[16];
    char target_host_str[256];
    char target_port_str[16];

    GetWindowTextA(proxy_port_edit, proxy_port_str, sizeof(proxy_port_str));
    GetWindowTextA(target_host_edit, target_host_str, sizeof(target_host_str));
    GetWindowTextA(target_port_edit, target_port_str, sizeof(target_port_str));

    USHORT proxy_port = (USHORT)atoi(proxy_port_str);
    USHORT target_port = (USHORT)atoi(target_port_str);

    if (!mitm_proxy->StartProxy(proxy_port, target_host_str, target_port))
    {
        LogMessage("Failed to start MITM proxy");
        return;
    }

    LogMessage("MITM proxy started on port " + std::to_string(proxy_port) + 
               " -> " + std::string(target_host_str) + ":" + std::to_string(target_port));
}

void GuiManager::OnStopProxy()
{
    mitm_proxy->StopProxy();
    LogMessage("MITM proxy stopped");
}

void GuiManager::OnPacketReceived(const NetworkPacket& packet)
{
    std::string direction = packet.is_incoming ? "IN" : "OUT";
    std::string packet_info = direction + " | " + 
                             std::to_string(packet.data.size()) + " bytes | " +
                             packet.source_ip + ":" + std::to_string(packet.source_port) + " -> " +
                             packet.dest_ip + ":" + std::to_string(packet.dest_port);

    SendMessageA(packet_listbox, LB_ADDSTRING, 0, (LPARAM)packet_info.c_str());

    // Auto-scroll to bottom
    int count = SendMessage(packet_listbox, LB_GETCOUNT, 0, 0);
    SendMessage(packet_listbox, LB_SETTOPINDEX, count - 1, 0);
}

LRESULT CALLBACK GuiManager::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    GuiManager* gui_manager = nullptr;

    if (uMsg == WM_NCCREATE)
    {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        gui_manager = (GuiManager*)cs->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)gui_manager);
    }
    else
    {
        gui_manager = (GuiManager*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    }

    if (!gui_manager)
    {
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    switch (uMsg)
    {
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_REFRESH_BTN:
            gui_manager->RefreshProcessList();
            break;
        case ID_PROCESS_LISTBOX:
            if (HIWORD(wParam) == LBN_SELCHANGE)
            {
                gui_manager->OnProcessSelected();
            }
            break;
        case ID_START_DEBUG_BTN:
            gui_manager->OnStartDebugging();
            break;
        case ID_STOP_DEBUG_BTN:
            gui_manager->OnStopDebugging();
            break;
        case ID_LAUNCH_EXE_BTN:
            gui_manager->OnLaunchExe();
            break;
        case ID_START_PROXY_BTN:
            gui_manager->OnStartProxy();
            break;
        case ID_STOP_PROXY_BTN:
            gui_manager->OnStopProxy();
            break;
        }
        break;

    case WM_CLOSE:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    return 0;
}

std::vector<GuiManager::ProcessInfo> GuiManager::EnumerateProcesses()
{
    std::vector<ProcessInfo> process_list;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return process_list;
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);

    if (Process32First(snapshot, &entry))
    {
        do
        {
            ProcessInfo info;
            info.pid = entry.th32ProcessID;
            
            // Convert wide string to narrow string
            int name_len = WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1, nullptr, 0, nullptr, nullptr);
            if (name_len > 0)
            {
                std::vector<char> name_buffer(name_len);
                WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1, name_buffer.data(), name_len, nullptr, nullptr);
                info.name = name_buffer.data();
            }

            // Get full path
            HANDLE proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid);
            if (proc_handle)
            {
                char path_buffer[MAX_PATH];
                DWORD path_size = sizeof(path_buffer);
                if (QueryFullProcessImageNameA(proc_handle, 0, path_buffer, &path_size))
                {
                    info.path = path_buffer;
                }
                CloseHandle(proc_handle);
            }

            process_list.push_back(info);

        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return process_list;
}
