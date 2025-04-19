#pragma once

#include <Windows.h>

namespace ioctl
{
    namespace codes
    {
        extern ULONG attach;
        extern ULONG read;
        extern ULONG write;
    }

    class Driver
    {
    public:
        Driver();
        ~Driver();

        bool attach_to_process(DWORD pid);

        template <class T>
        T read_memory(uintptr_t address);

        template <class T>
        void write_memory(uintptr_t address, const T& value);

    public:
        HANDLE driver_handle;

        struct Request
        {
            HANDLE process_id;
            PVOID target;
            PVOID buffer;
            SIZE_T size;
            SIZE_T return_size;
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
