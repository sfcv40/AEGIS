// Native API declarations that the Windows SDK does not ship (or ships only partly).
// Layouts follow the phnt headers.
#pragma once

#include <windows.h>
#include <winternl.h>

namespace aegis::nt {

constexpr NTSTATUS kInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
constexpr NTSTATUS kBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
constexpr NTSTATUS kBufferOverflow = static_cast<NTSTATUS>(0x80000005L);
constexpr NTSTATUS kNoMoreEntries = static_cast<NTSTATUS>(0x8000001AL);
constexpr NTSTATUS kMoreEntries = static_cast<NTSTATUS>(0x00000105L);

constexpr int kSystemModuleInformation = 11;
constexpr int kSystemKernelDebuggerInformation = 35;
constexpr int kSystemExtendedHandleInformation = 64;
constexpr int kSystemCodeIntegrityInformation = 103;
constexpr int kProcessCommandLineInformation = 60;

struct SystemHandleEntryEx {
  PVOID Object;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR HandleValue;
  ULONG GrantedAccess;
  USHORT CreatorBackTraceIndex;
  USHORT ObjectTypeIndex;
  ULONG HandleAttributes;
  ULONG Reserved;
};

struct SystemHandleInformationEx {
  ULONG_PTR NumberOfHandles;
  ULONG_PTR Reserved;
  SystemHandleEntryEx Handles[1];
};

struct ProcessModuleInformation {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
};

struct ProcessModules {
  ULONG NumberOfModules;
  ProcessModuleInformation Modules[1];
};

struct CodeIntegrityInformation {
  ULONG Length;
  ULONG CodeIntegrityOptions;
};

constexpr ULONG kCiEnabled = 0x01;
constexpr ULONG kCiTestSign = 0x02;
constexpr ULONG kCiDebugMode = 0x80;
constexpr ULONG kCiHvciKmci = 0x400;

struct KernelDebuggerInformation {
  BOOLEAN KernelDebuggerEnabled;
  BOOLEAN KernelDebuggerNotPresent;
};

struct ObjectDirectoryInformation {
  UNICODE_STRING Name;
  UNICODE_STRING TypeName;
};

using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtOpenDirectoryObjectFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtQueryDirectoryObjectFn = NTSTATUS(NTAPI*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

struct Api {
  NtQuerySystemInformationFn QuerySystemInformation = nullptr;
  NtQueryInformationProcessFn QueryInformationProcess = nullptr;
  NtOpenDirectoryObjectFn OpenDirectoryObject = nullptr;
  NtQueryDirectoryObjectFn QueryDirectoryObject = nullptr;
};

// Resolved once from ntdll.dll.
const Api& Get();

}  // namespace aegis::nt
