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

    // Show loading message
    MessageBoxA(nullptr, 
               "Advanced Debug Manager\n\n"
               "The application will now:\n"
               "1. Download kdmapper (if needed)\n"
               "2. Map the kernel driver\n"
               "3. Initialize debug environment\n\n"
               "This may take a few moments and requires administrator privileges.\n"
               "Please ensure antivirus real-time protection is disabled.",
               "Initializing", 
               MB_OK | MB_ICONINFORMATION);

    // Initialize kdmapper and map driver
    if (!gui_manager->InitializeKdMapper())
    {
        int result = MessageBoxA(nullptr,
                               "Failed to initialize kdmapper and map driver!\n\n"
                               "You can continue without the kernel driver, but some features will be limited.\n\n"
                               "Continue anyway?",
                               "Initialization Warning",
                               MB_YESNO | MB_ICONWARNING);
        
        if (result == IDNO)
        {
            CoUninitialize();
            return 1;
        }
    }

    // Final driver check for user feedback
    ioctl::Driver driver;
    if (driver.driver_handle == INVALID_HANDLE_VALUE)
    {
        MessageBoxA(nullptr, 
                   "Warning: Kernel driver not accessible.\n\n"
                   "Features that will be limited:\n"
                   "- Advanced anti-anti-debug bypasses\n"
                   "- Process hiding capabilities\n"
                   "- Kernel-level memory protection\n\n"
                   "Basic debugging and MITM proxy will still work.\n"
                   "Make sure the driver is loaded and you have administrator privileges.",
                   "Driver Warning", 
                   MB_OK | MB_ICONWARNING);
    }
    else
    {
        MessageBoxA(nullptr,
                   "✅ Initialization Complete!\n\n"
                   "✓ kdmapper downloaded\n"
                   "✓ Kernel driver mapped\n" 
                   "✓ Driver communication established\n"
                   "✓ All features available\n\n"
                   "Ready for advanced debugging!",
                   "Success",
                   MB_OK | MB_ICONINFORMATION);
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