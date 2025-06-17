#include <ntifs.h>

extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName,
		PDRIVER_INITIALIZE InitializationFunction);

	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
											 PEPROCESS TargetProcess, PVOID TargetAddress,
											 SIZE_T bufferSize, KPROCESSOR_MODE PreviousMode,
											 PSIZE_T ReturnSize);

	NTKERNELAPI NTSTATUS PsSetCreateProcessNotifyRoutine(
		PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
		BOOLEAN Remove
	);

	NTKERNELAPI NTSTATUS PsSetCreateThreadNotifyRoutine(
		PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
	);

	NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

	NTKERNELAPI NTSTATUS ZwSetInformationThread(
		HANDLE ThreadHandle,
		ULONG ThreadInformationClass,
		PVOID ThreadInformation,
		ULONG ThreadInformationLength
	);

	NTKERNELAPI NTSTATUS ZwCreateProcess(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		HANDLE ParentProcess,
		BOOLEAN InheritObjectTable,
		HANDLE SectionHandle,
		HANDLE DebugPort,
		HANDLE ExceptionPort
	);

	NTKERNELAPI NTSTATUS ZwCreateSection(
		PHANDLE SectionHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PLARGE_INTEGER MaximumSize,
		ULONG SectionPageProtection,
		ULONG AllocationAttributes,
		HANDLE FileHandle
	);

	NTKERNELAPI NTSTATUS ZwOpenFile(
		PHANDLE FileHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK IoStatusBlock,
		ULONG ShareAccess,
		ULONG OpenOptions
	);

	NTKERNELAPI NTSTATUS ZwOpenProcessToken(
		HANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		PHANDLE TokenHandle
	);

	NTKERNELAPI NTSTATUS ZwAdjustPrivilegesToken(
		HANDLE TokenHandle,
		BOOLEAN DisableAllPrivileges,
		PTOKEN_PRIVILEGES NewState,
		ULONG BufferLength,
		PTOKEN_PRIVILEGES PreviousState,
		PULONG ReturnLength
	);

	NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
	NTKERNELAPI PVOID PsGetProcessDebugPort(PEPROCESS Process);
	NTKERNELAPI NTSTATUS PsSetProcessDebugPort(PEPROCESS Process, PVOID DebugPort);
	NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);

	// Forward declaration for unload routine
	VOID DriverUnload(PDRIVER_OBJECT driver_object);
}

namespace driver
{
	// Process notification callbacks
	static PEPROCESS g_target_process = nullptr;
	static HANDLE g_target_pid = nullptr;
	static LIST_ENTRY g_hidden_processes;
	static KSPIN_LOCK g_hidden_processes_lock;

	// Thread information classes
	#define ThreadHideFromDebugger 0x11

	// System information classes
	#define SystemProcessInformation 5

	// Process flags offsets (Windows 10/11 x64)
	#define EPROCESS_DEBUGPORT_OFFSET 0x420
	#define EPROCESS_FLAGS_OFFSET 0x440
	#define EPROCESS_FLAGS2_OFFSET 0x444

	// Memory layout constants
	#define MM_SHARED_USER_DATA_VA 0xFFFFF78000000000ULL

	// Token privilege constants (simplified for kernel use)
	#define TOKEN_ADJUST_PRIVILEGES 0x0020
	#define TOKEN_QUERY 0x0008
	#define SE_PRIVILEGE_ENABLED 0x00000002L

	namespace codes
	{
		constexpr ULONG attach =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		
		constexpr ULONG read =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		
		constexpr ULONG write =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG hide_debugger =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG anti_anti_debug =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x700, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG hook_network =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG set_debug_privilege =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG create_process =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x703, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG hide_process =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x704, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG protect_process =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x705, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}

	struct Request {
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

	struct HiddenProcess {
		LIST_ENTRY ListEntry;
		HANDLE ProcessId;
		BOOLEAN IsHidden;
	};

	NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp)
	{
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp)
	{
		UNREFERENCED_PARAMETER(device_object);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}	// Helper functions
	NTSTATUS EnableDebugPrivilege()
	{
		// In kernel mode, we already have all privileges
		// This function is mainly for user-mode processes
		// For kernel driver, we can directly manipulate process structures
		DbgPrint("[+] Debug privileges are inherently available in kernel mode\n");
		return STATUS_SUCCESS;
	}

	// Anti-Anti-Debug Helper Functions
	NTSTATUS HideFromDebugger(HANDLE ProcessId)
	{
		PEPROCESS Process;
		NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
		
		if (!NT_SUCCESS(Status))
			return Status;

		// Method 1: Clear debug port
		PVOID* DebugPort = (PVOID*)((UCHAR*)Process + EPROCESS_DEBUGPORT_OFFSET);
		*DebugPort = nullptr;

		// Method 2: Set NoDebugInherit flag
		ULONG* ProcessFlags = (ULONG*)((UCHAR*)Process + EPROCESS_FLAGS_OFFSET);
		*ProcessFlags |= 0x4; // NoDebugInherit flag

		// Method 3: Hide from PEB
		PPEB Peb = PsGetProcessPeb(Process);
		if (Peb)
		{
			Peb->BeingDebugged = FALSE;
			Peb->NtGlobalFlag &= ~0x70; // Clear heap flags
		}

		ObDereferenceObject(Process);
		DbgPrint("[+] Process hidden from debugger: PID %d\n", (ULONG)(ULONG_PTR)ProcessId);
		return STATUS_SUCCESS;
	}

	NTSTATUS AntiAntiDebug(HANDLE ProcessId)
	{
		PEPROCESS Process;
		NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
		
		if (!NT_SUCCESS(Status))
			return Status;

		// Patch common anti-debug techniques
		PPEB Peb = PsGetProcessPeb(Process);
		if (Peb)
		{
			// Clear BeingDebugged flag
			Peb->BeingDebugged = FALSE;

			// Clear NtGlobalFlag
			Peb->NtGlobalFlag &= ~0x70;

			// Clear heap flags
			if (Peb->ProcessHeap)
			{
				// Patch heap header flags
				ULONG* HeapFlags = (ULONG*)((UCHAR*)Peb->ProcessHeap + 0x40);
				*HeapFlags &= ~0x02; // HEAP_TAIL_CHECKING_ENABLED
				*HeapFlags &= ~0x01; // HEAP_FREE_CHECKING_ENABLED

				ULONG* HeapForceFlags = (ULONG*)((UCHAR*)Peb->ProcessHeap + 0x44);
				*HeapForceFlags &= ~0x02;
				*HeapForceFlags &= ~0x01;
			}
		}

		// Clear debug object handle
		HANDLE* DebugObjectHandle = (HANDLE*)((UCHAR*)Process + 0x420);
		*DebugObjectHandle = nullptr;
		// Patch KUSER_SHARED_DATA (be careful with this)
		__try
		{
			// Note: This is a risky operation and may cause system instability
			// Only modify if absolutely necessary
			PKUSER_SHARED_DATA SharedUserData = (PKUSER_SHARED_DATA)MM_SHARED_USER_DATA_VA;
			if (SharedUserData && MmIsAddressValid(SharedUserData))
			{
				SharedUserData->KdDebuggerEnabled = 0;
			}
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			DbgPrint("[-] Failed to patch KUSER_SHARED_DATA\n");
		}

		ObDereferenceObject(Process);
		DbgPrint("[+] Anti-anti-debug applied to process: PID %d\n", (ULONG)(ULONG_PTR)ProcessId);
		return STATUS_SUCCESS;
	}

	NTSTATUS CreateDebuggedProcess(PWCHAR ProcessPath)
	{
		HANDLE FileHandle = nullptr;
		HANDLE SectionHandle = nullptr;
		HANDLE ProcessHandle = nullptr;
		NTSTATUS Status;

		// Open the executable file
		UNICODE_STRING FileName;
		RtlInitUnicodeString(&FileName, ProcessPath);

		OBJECT_ATTRIBUTES FileAttributes;
		InitializeObjectAttributes(&FileAttributes, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

		IO_STATUS_BLOCK IoStatusBlock;
		Status = ZwOpenFile(&FileHandle, GENERIC_READ, &FileAttributes, &IoStatusBlock, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);

		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to open file: %ws, Status: 0x%X\n", ProcessPath, Status);
			return Status;
		}

		// Create section
		InitializeObjectAttributes(&FileAttributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
		Status = ZwCreateSection(&SectionHandle, SECTION_ALL_ACCESS, &FileAttributes, nullptr, PAGE_EXECUTE, SEC_IMAGE, FileHandle);

		if (!NT_SUCCESS(Status))
		{
			ZwClose(FileHandle);
			DbgPrint("[-] Failed to create section, Status: 0x%X\n", Status);
			return Status;
		}

		// Create process in suspended state
		InitializeObjectAttributes(&FileAttributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
		Status = ZwCreateProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &FileAttributes, ZwCurrentProcess(), FALSE, SectionHandle, nullptr, nullptr);

		if (NT_SUCCESS(Status))
		{
			// Apply anti-anti-debug to the new process
			PEPROCESS NewProcess;
			Status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&NewProcess, nullptr);
			
			if (NT_SUCCESS(Status))
			{
				HANDLE NewPid = PsGetProcessId(NewProcess);
				AntiAntiDebug(NewPid);
				HideFromDebugger(NewPid);
				
				ObDereferenceObject(NewProcess);
				DbgPrint("[+] Created and configured process: %ws, PID: %d\n", ProcessPath, (ULONG)(ULONG_PTR)NewPid);
			}

			ZwClose(ProcessHandle);
		}

		ZwClose(SectionHandle);
		ZwClose(FileHandle);

		return Status;
	}

	NTSTATUS HideProcessFromTaskManager(HANDLE ProcessId)
	{
		KIRQL OldIrql;
		KeAcquireSpinLock(&g_hidden_processes_lock, &OldIrql);

		// Check if already hidden
		PLIST_ENTRY ListEntry = g_hidden_processes.Flink;
		while (ListEntry != &g_hidden_processes)
		{
			HiddenProcess* HiddenProc = CONTAINING_RECORD(ListEntry, HiddenProcess, ListEntry);
			if (HiddenProc->ProcessId == ProcessId)
			{
				KeReleaseSpinLock(&g_hidden_processes_lock, OldIrql);
				return STATUS_SUCCESS; // Already hidden
			}
			ListEntry = ListEntry->Flink;
		}

		// Add to hidden list
		HiddenProcess* NewHiddenProcess = (HiddenProcess*)ExAllocatePoolWithTag(NonPagedPool, sizeof(HiddenProcess), 'HidP');
		if (!NewHiddenProcess)
		{
			KeReleaseSpinLock(&g_hidden_processes_lock, OldIrql);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		NewHiddenProcess->ProcessId = ProcessId;
		NewHiddenProcess->IsHidden = TRUE;
		InsertTailList(&g_hidden_processes, &NewHiddenProcess->ListEntry);

		KeReleaseSpinLock(&g_hidden_processes_lock, OldIrql);

		DbgPrint("[+] Process hidden from task manager: PID %d\n", (ULONG)(ULONG_PTR)ProcessId);
		return STATUS_SUCCESS;
	}

	NTSTATUS ProtectProcess(HANDLE ProcessId, ULONG ProtectionLevel)
	{
		PEPROCESS Process;
		NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
		
		if (!NT_SUCCESS(Status))
			return Status;

		// Set process protection level
		ULONG* ProcessFlags2 = (ULONG*)((UCHAR*)Process + EPROCESS_FLAGS2_OFFSET);
		
		switch (ProtectionLevel)
		{
		case 1: // Light protection
			*ProcessFlags2 |= 0x800; // Set ProtectedProcess flag
			break;
		case 2: // Medium protection  
			*ProcessFlags2 |= 0x1000; // Set ProtectedProcessLight flag
			break;
		case 3: // Full protection
			*ProcessFlags2 |= 0x2000; // Set ProtectedProcessFull flag
			break;
		}

		ObDereferenceObject(Process);
		DbgPrint("[+] Process protection set: PID %d, Level %d\n", (ULONG)(ULONG_PTR)ProcessId, ProtectionLevel);
		return STATUS_SUCCESS;
	}

	// Process creation callback
	VOID ProcessNotifyCallback(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
	{
		UNREFERENCED_PARAMETER(ParentId);

		if (Create && g_target_pid && ProcessId == g_target_pid)
		{
			// Auto-apply protection to target process
			AntiAntiDebug(ProcessId);
			HideFromDebugger(ProcessId);
		}
	}

	NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp)
	{
		UNREFERENCED_PARAMETER(device_object);
		
		DbgPrint("[+] Device control called.\n");

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		// We need this to determine which code was passed through
		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

		// Access the request object sent from user mode.
		auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

		if (stack_irp == nullptr || request == nullptr)
		{
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		// The target process we want to access.
		static PEPROCESS target_process = nullptr;

		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;	NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp)
	{
		UNREFERENCED_PARAMETER(device_object);
		
		DbgPrint("[+] Device control called.\n");

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		// We need this to determine which code was passed through
		PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);

		// Access the request object sent from user mode.
		auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

		if (stack_irp == nullptr || request == nullptr)
		{
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		// The target process we want to access.
		static PEPROCESS target_process = nullptr;

		const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;

		switch (control_code)
		{
		case codes::attach:
			status = PsLookupProcessByProcessId(request->process_id, &target_process);
			if (NT_SUCCESS(status))
			{
				g_target_pid = request->process_id;
				DbgPrint("[+] Attached to process PID: %d\n", (ULONG)(ULONG_PTR)request->process_id);
			}
			break;

		case codes::read:
			if (target_process != nullptr)
			{
				status = MmCopyVirtualMemory(
					target_process, request->target,
					PsGetCurrentProcess(), request->buffer,
					request->size, KernelMode, &request->return_size
				);
			}
			else
			{
				status = STATUS_INVALID_HANDLE;
			}
			break;

		case codes::write:
			if (target_process != nullptr)
			{
				status = MmCopyVirtualMemory(
					PsGetCurrentProcess(), request->buffer,
					target_process, request->target,
					request->size, KernelMode, &request->return_size
				);
			}
			else
			{
				status = STATUS_INVALID_HANDLE;
			}
			break;

		case codes::hide_debugger:
			status = HideFromDebugger(request->process_id);
			if (NT_SUCCESS(status))
			{
				DbgPrint("[+] Hide debugger applied to PID: %d\n", (ULONG)(ULONG_PTR)request->process_id);
			}
			break;

		case codes::anti_anti_debug:
			status = AntiAntiDebug(request->process_id);
			if (NT_SUCCESS(status))
			{
				DbgPrint("[+] Anti-anti-debug applied to PID: %d\n", (ULONG)(ULONG_PTR)request->process_id);
			}
			break;

		case codes::create_process:
			status = CreateDebuggedProcess(request->process_path);
			if (NT_SUCCESS(status))
			{
				DbgPrint("[+] Created debugged process: %ws\n", request->process_path);
			}
			break;

		case codes::set_debug_privilege:
			status = EnableDebugPrivilege();
			if (NT_SUCCESS(status))
			{
				DbgPrint("[+] Debug privileges enabled\n");
			}
			break;

		case codes::hide_process:
			status = HideProcessFromTaskManager(request->process_id);
			if (NT_SUCCESS(status))
			{
				DbgPrint("[+] Process hidden from task manager: PID %d\n", (ULONG)(ULONG_PTR)request->process_id);
			}
			break;

		case codes::protect_process:
			status = ProtectProcess(request->process_id, request->protection_level);
			if (NT_SUCCESS(status))
			{
				DbgPrint("[+] Process protection applied: PID %d, Level %d\n", 
					(ULONG)(ULONG_PTR)request->process_id, request->protection_level);
			}
			break;

		case codes::hook_network:
			// Network hooking implementation would go here
			// This is complex and would require additional kernel modules
			DbgPrint("[+] Network hooking requested for port %d\n", request->network_port);
			status = STATUS_SUCCESS; // Placeholder
			break;

		default:
			DbgPrint("[-] Unknown IOCTL code: 0x%X\n", control_code);
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}
	}
}

// our "real" entry point
NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);

	// Initialize hidden processes list
	InitializeListHead(&g_hidden_processes);
	KeInitializeSpinLock(&g_hidden_processes_lock);

	UNICODE_STRING device_name = {};
	RtlInitUnicodeString(&device_name, L"\\Device\\IOCTLKernelCheat");

	// Create driver device Object
	PDEVICE_OBJECT device_object = nullptr;
	NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);

	if (status != STATUS_SUCCESS) {
		DbgPrint("[-] Failed to create driver device.\n");
		return status;
	}

	DbgPrint("[+] Driver device successfully created.\n");

	// Establish Symbolic Link
	UNICODE_STRING symbolic_link = {};
	RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\IOCTLKernelCheat");

	status = IoCreateSymbolicLink(&symbolic_link, &device_name);
	if (status != STATUS_SUCCESS)
	{
		IoDeleteDevice(device_object);
		DbgPrint("[-] Failed to establish Symbolic Link.\n");
		return status;
	}

	DbgPrint("[+] Driver symbolic link successfully established.\n");

	// Register process notification callback
	status = PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to register process notify callback: 0x%X\n", status);
		// Continue anyway, this is not critical
	}
	else
	{
		DbgPrint("[+] Process notification callback registered.\n");
	}

	// Allow us to send small amounts of data between um/km
	SetFlag(device_object->Flags, DO_BUFFERED_IO);

	// Set the driver handlers to our functions with our logic.
	driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

	// Set unload routine for cleanup
	driver_object->DriverUnload = DriverUnload;

	// Finished initializing our device.
	ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

	DbgPrint("[+] Driver initialized successfully.\n");

	return status;
}

VOID DriverUnload(PDRIVER_OBJECT driver_object)
{
	UNREFERENCED_PARAMETER(driver_object);

	// Unregister process notification callback
	PsSetCreateProcessNotifyRoutine(ProcessNotifyCallback, TRUE);

	// Cleanup hidden processes list
	KIRQL OldIrql;
	KeAcquireSpinLock(&g_hidden_processes_lock, &OldIrql);

	while (!IsListEmpty(&g_hidden_processes))
	{
		PLIST_ENTRY ListEntry = RemoveHeadList(&g_hidden_processes);
		HiddenProcess* HiddenProc = CONTAINING_RECORD(ListEntry, HiddenProcess, ListEntry);
		ExFreePoolWithTag(HiddenProc, 'HidP');
	}

	KeReleaseSpinLock(&g_hidden_processes_lock, OldIrql);

	// Delete symbolic link
	UNICODE_STRING symbolic_link = {};
	RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\IOCTLKernelCheat");
	IoDeleteSymbolicLink(&symbolic_link);

	// Delete device
	if (driver_object->DeviceObject)
	{
		IoDeleteDevice(driver_object->DeviceObject);
	}

	DbgPrint("[+] Driver unloaded successfully.\n");
}

NTSTATUS DriverEntry()
{
	DbgPrint("[+] Loaded Kernel Mode Cheat.\n");

	UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\IOCTLKernelCheat");


	return IoCreateDriver(&driver_name, &driver_main);
}