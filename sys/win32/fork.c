/*
#define _WIN32_WINNT 0x0600
*/
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winnt.h>
#include <ntdef.h>
#include <stdio.h>
#include <errno.h>
#include <process.h>

#define RTL_CLONE_FLAGS (CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | \
                         CLONE_PROCESS_FLAGS_INHERIT_HANDLES)

typedef struct _CLIENT_ID {
	void *UniqueProcess;
	void *UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID EntryPoint;
	ULONG StackZeroBits;
	ULONG StackReserved;
	ULONG StackCommit;
	ULONG ImageSubsystem;
	WORD SubSystemVersionLow;
	WORD SubSystemVersionHigh;
	ULONG Unknown1;
	ULONG ImageCharacteristics;
	ULONG ImageMachineType;
	ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG Size;
	HANDLE Process;
	HANDLE Thread;
	CLIENT_ID ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

#define CLONE_PROCESS_FLAGS_CREATE_SUSPENDED    0x00000001
#define CLONE_PROCESS_FLAGS_INHERIT_HANDLES     0x00000002
#define CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE      0x00000004
#define CLONE_PARENT                            0
#define CLONE_CHILD                             297

typedef NTSTATUS 
(*w32_clone)(ULONG flags,
               PSECURITY_DESCRIPTOR process_desc,
               PSECURITY_DESCRIPTOR thread_dest,
               HANDLE dbg,
               PRTL_USER_PROCESS_INFORMATION info);

HMODULE ntdll;
w32_clone w32_fork;

void
fork_init(void)
{
	if (!(ntdll = GetModuleHandle("ntdll.dll")))
		return;
	if (!(w32_fork = (w32_clone)GetProcAddress(ntdll, "RtlCloneUserProcess")))
		return; 
}

int
fork(void)
{
	RTL_USER_PROCESS_INFORMATION info;
	NTSTATUS result;

	if (w32_fork == NULL)
		return -ENOSYS;
	/* lets do this */
	result = w32_fork(RTL_CLONE_FLAGS, NULL, NULL, NULL, &info);
	if (result == CLONE_PARENT) {
		pid_t pid = GetProcessId(info.Process);
		ResumeThread(info.Thread);
		CloseHandle(info.Process);
		CloseHandle(info.Thread);
		return pid;
	} else if (result == CLONE_CHILD) {
		/* fix stdio */
		AllocConsole();
		return 0;
	} else
		return -1;

	return -1;
}
