#pragma once

#include <Windows.h>

namespace ioctl
{
    namespace codes
    {
        extern ULONG attach;
        extern ULONG read;
        extern ULONG write;
        extern ULONG hide_debugger;
        extern ULONG anti_anti_debug;
        extern ULONG hook_network;
        extern ULONG set_debug_privilege;
        extern ULONG create_process;
        extern ULONG hide_process;
        extern ULONG protect_process;
    }    class Driver
    {
    public:
        Driver();
        ~Driver();

        bool attach_to_process(DWORD pid);
        bool hide_debugger(DWORD pid);
        bool enable_anti_anti_debug(DWORD pid);
        bool set_debug_privilege();
        bool create_process_for_debug(const std::wstring& process_path);
        bool hide_process_from_task_manager(DWORD pid);
        bool protect_process(DWORD pid, ULONG protection_level);
        bool hook_network_traffic(ULONG port);

        template <class T>
        T read_memory(uintptr_t address);

        template <class T>
        void write_memory(uintptr_t address, const T& value);

    public:
        HANDLE driver_handle;

        struct Request
        {
            HANDLE process_id;
            HANDLE thread_id;
            PVOID target;
            PVOID buffer;
            SIZE_T size;
            SIZE_T return_size;
            WCHAR process_path[260];
            BOOLEAN hide_from_debugger;
            ULONG network_port;
            ULONG protection_level;
        };
    };
}

template <class T>
T ioctl::Driver::read_memory(uintptr_t address)
{
    T temp = {};

    Request r;
    r.target = reinterpret_cast<PVOID>(address);
    r.buffer = &temp;
    r.size = sizeof(temp);

    DeviceIoControl(driver_handle, codes::read, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);

    return temp;
}

template <class T>
void ioctl::Driver::write_memory(uintptr_t address, const T& value)
{
    Request r;
    r.target = reinterpret_cast<PVOID>(address);
    r.buffer = (PVOID)&value;
    r.size = sizeof(T);

    DeviceIoControl(driver_handle, codes::write, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
}
