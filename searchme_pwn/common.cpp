#include "stdafx.h"
#include "common.h"

PNtQuerySystemInformation NtQuerySystemInformation;
PNtCreateKeyedEvent NtCreateKeyedEvent;
PNtCreateDirectoryObject NtCreateDirectoryObject;
PNtCreateSymbolicLinkObject NtCreateSymbolicLinkObject;
PDbgPrintEx DbgPrintEx;

void winerror(const char* prefix) {
	char buf[4096];
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buf, sizeof(buf), NULL);
	printf("%s: %s\n", prefix, buf);
	exit(1);
}

void init_funcs() {
	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	HMODULE kernel32 = GetModuleHandle(TEXT("kernel32"));
	NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (!NtQuerySystemInformation)
		winerror("Resolving NtQuerySystemInformation");
	NtCreateKeyedEvent = (PNtCreateKeyedEvent)GetProcAddress(ntdll, "NtCreateKeyedEvent");
	if (!NtCreateKeyedEvent)
		winerror("Resolving NtCreateKeyedEvent");
	NtCreateDirectoryObject = (PNtCreateDirectoryObject)GetProcAddress(ntdll, "NtCreateDirectoryObject");
	if (!NtCreateDirectoryObject)
		winerror("Resolving NtCreateDirectoryObject");
	NtCreateSymbolicLinkObject = (PNtCreateSymbolicLinkObject)GetProcAddress(ntdll, "NtCreateSymbolicLinkObject");
	if (!NtCreateSymbolicLinkObject)
		winerror("Resolving NtCreateSymbolicLinkObject");
	DbgPrintEx = (PDbgPrintEx)GetProcAddress(ntdll, "DbgPrintEx");
	if (!DbgPrintEx)
		winerror("Resolving DbgPrintEx");

	//printf("HMValidateHandle @ %p\n", HMValidateHandle);
}