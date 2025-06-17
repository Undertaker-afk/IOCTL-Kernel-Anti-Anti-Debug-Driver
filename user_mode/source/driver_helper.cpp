#include "../headers/driver_helper.h"

namespace ioctl
{
    namespace codes
    {
        ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG hide_debugger = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG anti_anti_debug = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG hook_network = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG set_debug_privilege = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG create_process = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG hide_process = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x704, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG protect_process = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x705, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    Driver::Driver()
    {
        driver_handle = CreateFile(L"\\\\.\\IOCTLKernelCheat", GENERIC_ALL, 0, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    Driver::~Driver()
    {
        if (driver_handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(driver_handle);
            driver_handle = INVALID_HANDLE_VALUE;
        }
    }    bool Driver::attach_to_process(DWORD pid)
    {
        Request r = {};
        r.process_id = reinterpret_cast<HANDLE>(pid);

        return DeviceIoControl(driver_handle, codes::attach, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }

    bool Driver::hide_debugger(DWORD pid)
    {
        Request r = {};
        r.process_id = reinterpret_cast<HANDLE>(pid);

        return DeviceIoControl(driver_handle, codes::hide_debugger, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }

    bool Driver::enable_anti_anti_debug(DWORD pid)
    {
        Request r = {};
        r.process_id = reinterpret_cast<HANDLE>(pid);

        return DeviceIoControl(driver_handle, codes::anti_anti_debug, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }

    bool Driver::set_debug_privilege()
    {
        Request r = {};

        return DeviceIoControl(driver_handle, codes::set_debug_privilege, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }    bool Driver::create_process_for_debug(const std::wstring& process_path)
    {
        Request r = {};
        wcsncpy_s(r.process_path, process_path.c_str(), _TRUNCATE);

        return DeviceIoControl(driver_handle, codes::create_process, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }

    bool Driver::hide_process_from_task_manager(DWORD pid)
    {
        Request r = {};
        r.process_id = reinterpret_cast<HANDLE>(pid);

        return DeviceIoControl(driver_handle, codes::hide_process, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }

    bool Driver::protect_process(DWORD pid, ULONG protection_level)
    {
        Request r = {};
        r.process_id = reinterpret_cast<HANDLE>(pid);
        r.protection_level = protection_level;

        return DeviceIoControl(driver_handle, codes::protect_process, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }

    bool Driver::hook_network_traffic(ULONG port)
    {
        Request r = {};
        r.network_port = port;

        return DeviceIoControl(driver_handle, codes::hook_network, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }
}
