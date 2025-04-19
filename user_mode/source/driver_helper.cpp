#include "../headers/driver_helper.h"

namespace ioctl
{
    namespace codes
    {
        ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
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
    }

    bool Driver::attach_to_process(DWORD pid)
    {
        Request r = {};
        r.process_id = reinterpret_cast<HANDLE>(pid);

        return DeviceIoControl(driver_handle, codes::attach, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
    }
}
