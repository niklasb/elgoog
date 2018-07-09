#pragma once

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <subauth.h>
#include <Winuser.h>
#include <direct.h>


#ifdef _WIN64
typedef void*(NTAPI *lHMValidateHandle)(HWND h, int type);
#else
typedef void*(__fastcall *lHMValidateHandle)(HWND h, int type);
#endif

typedef struct _SYSTEM_HANDLE
{
	PVOID Object;
	HANDLE UniqueProcessId;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR HandleCount;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);

typedef NTSTATUS(WINAPI *PNtCreateKeyedEvent)(
	OUT PHANDLE handle, IN ACCESS_MASK access,
	IN void* attr, IN ULONG flags
	);

typedef NTSTATUS(WINAPI *PNtCreateDirectoryObject)(
	OUT PHANDLE handle, IN ACCESS_MASK access,
	IN void* attr
	);

typedef NTSTATUS(WINAPI *PNtCreateSymbolicLinkObject)(
	OUT PHANDLE handle, IN ACCESS_MASK access,
	IN void* attr, IN PUNICODE_STRING LinkTarget
	);


typedef ULONG(__cdecl * PDbgPrintEx)(
	_In_ ULONG ComponentId,
	_In_ ULONG Level,
	_In_ PCSTR Format,
	...
	);

extern lHMValidateHandle HMValidateHandle;
extern PNtQuerySystemInformation NtQuerySystemInformation;
extern PNtCreateKeyedEvent NtCreateKeyedEvent;
extern PNtCreateDirectoryObject NtCreateDirectoryObject;
extern PNtCreateSymbolicLinkObject NtCreateSymbolicLinkObject;
extern PDbgPrintEx DbgPrintEx;


#define LOG(fmt, ...) DbgPrintEx(77 /*DPFLTR_IHVDRIVER_ID*/, 3, fmt, __VA_ARGS__)

void winerror(const char* prefix);
void init_funcs();