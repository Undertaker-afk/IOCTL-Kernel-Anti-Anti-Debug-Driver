#include <iostream>
#include <memory>

#ifdef _WIN32
#include <windows.h>
#include "../headers/gui_manager.h"
#include "../headers/driver_helper.h"
#include "../headers/error_helper.h"
#endif

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Initialize COM for file dialogs
    CoInitialize(nullptr);

    // Create and initialize GUI manager
    auto gui_manager = std::make_unique<GuiManager>();
    
    if (!gui_manager->Initialize())
    {
        MessageBoxA(nullptr, "Failed to initialize application", "Error", MB_OK | MB_ICONERROR);
        CoUninitialize();
        return 1;
    }

    // Check if driver is accessible
    ioctl::Driver driver;
    if (driver.driver_handle == INVALID_HANDLE_VALUE)
    {
        MessageBoxA(nullptr, 
                   "Warning: Kernel driver not accessible.\n"
                   "Some features may not work properly.\n"
                   "Make sure the driver is loaded and you have administrator privileges.",
                   "Driver Warning", 
                   MB_OK | MB_ICONWARNING);
    }

    // Run the application
    gui_manager->Run();

    // Cleanup
    gui_manager->Shutdown();
    CoUninitialize();

    return 0;
}
#endif

// Console entry point for debugging
int main()
{
#ifdef _WIN32
    return WinMain(GetModuleHandle(nullptr), nullptr, GetCommandLineA(), SW_SHOW);
#else
    std::cout << "This application is designed for Windows only." << std::endl;
    return 1;
#endif
}