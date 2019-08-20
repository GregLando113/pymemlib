from ctypes import (
    Structure, 
    Array, 
    Union, 
    POINTER, 
    sizeof, 
    byref
)
from ctypes.wintypes import *

import os
import sys
import ctypes
import struct
import functools
import inspect

# types not in wintypes
PVOID = ctypes.c_void_p
SIZE_T = ctypes.c_size_t
ULONG_PTR = SIZE_T
ULONGLONG = ctypes.c_ulonglong
NTSTATUS = LONG

# probably a better way
PROCESS_IS_64_BITS = sys.maxsize > 2 ** 32

# standard access rights
DELETE = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
SYNCHRONIZE = 0x00100000
STANDARD_RIGHTS_ALL = 0x001F0000

PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_SET_SESSIONID = 0x0004
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLER = 0x0040
PROCESS_CREATE_PROCESS = 0x0080
PROCESS_SET_QUOTA = 0x0100
PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SUSPEN_RESUME = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_SET_LIMITED_INFORMATION = 0x2000
PROCESS_ALL_ACCESS = STANDARD_RIGHTS_ALL | 0xFFFF

THREAD_TERMINATE = 0x0001
THREAD_SUSPEND_RESUME = 0x0002
THREAD_GET_CONTEXT = 0x0004
THREAD_SET_CONTEXT = 0x0008
THREAD_QUERY_INFORMATION = 0x0010
THREAD_SET_INFORMATION = 0x0020
THREAD_SET_THREAD_TOKEN = 0x0080
THREAD_IMPERSONATE = 0x0100
THREAD_DIRECT_IMPERSONATION = 0x0200
THREAD_SET_LIMITED_INFORMATION = 0x0400
THREAD_QUERY_LIMITED_INFORMATION = 0x0800
THREAD_RESUME = 0x1000
THREAD_ALL_ACCESS = STANDARD_RIGHTS_ALL | 0xFFFF

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
TH32CS_SNAPALL = 0x000000FF
TH32CS_INHERIT = 0x80000000

CONTEXT_CONTROL = 0x00010001  # SS:SP, CS:IP, FLAGS, BP
CONTEXT_INTEGER = 0x00010002  # AX, BX, CX, DX, SI, DI
CONTEXT_SEGMENTS = 0x00010004  # DS, ES, FS, GS
CONTEXT_FLOATING_POINT = 0x00010008  # 387 state
CONTEXT_DEBUG_REGISTERS = 0x00010010  # DB 0-3,6,7
CONTEXT_EXTENDED_REGISTERS = 0x00010020  # cpu specific extensions
CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS

EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_IN_PAGE_ERROR = 0xC0000006
EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D
EXCEPTION_NONCONTINUABLE_EXCEPTION = 0xC0000025
EXCEPTION_INVALID_DISPOSITION = 0xC0000026
EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C
EXCEPTION_FLT_DENORMAL_OPERAND = 0xC000008D
EXCEPTION_FLT_DIVIDE_BY_ZERO = 0xC000008E
EXCEPTION_FLT_INEXACT_RESULT = 0xC000008F
EXCEPTION_FLT_INVALID_OPERATION = 0xC0000090
EXCEPTION_FLT_OVERFLOW = 0xC0000091
EXCEPTION_FLT_STACK_CHECK = 0xC0000092
EXCEPTION_FLT_UNDERFLOW = 0xC0000093
EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094
EXCEPTION_INT_OVERFLOW = 0xC0000095
EXCEPTION_PRIV_INSTRUCTION = 0xC0000096
EXCEPTION_STACK_OVERFLOW = 0xC00000FD

ThreadBasicInformation = 0
ThreadTimes = 1
ThreadPriority = 2
ThreadBasePriority = 3
ThreadAffinityMask = 4
ThreadImpersonationToken = 5
ThreadDescriptorTableEntry = 6
ThreadEnableAlignmentFaultFixup = 7
ThreadEventPair = 8
ThreadQuerySetWin32StartAddress = 9
ThreadZeroTlsCell = 10
ThreadPerformanceCount = 11
ThreadAmILastThread = 12
ThreadIdealProcessor = 13
ThreadPriorityBoost = 14
ThreadSetTlsArrayAddress = 15
ThreadIsIoPending = 16
ThreadHideFromDebugger = 17

IGNORE = 0
INFINITE = 0xFFFFFFFF

WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF

MAX_PATH = 260

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

# Make kernel32 independant of windll which may be unpredictable.
kernel32 = ctypes.WinDLL("kernel32.dll")
ntdll = ctypes.WinDLL("ntdll.dll")


class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("th32ModuleID", DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage", DWORD),
        ("ProccntUsage", DWORD),
        ("modBaseAddr", LPVOID),
        ("modBaseSize", DWORD),
        ("hModule", HMODULE),
        ("szModule", CHAR * 256),
        ("szExePath", CHAR * MAX_PATH),
    ]

    def __init__(self):
        self.dwSize = sizeof(self)


class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ProcessID", DWORD),
        ("th32DefaultHeapID", LPVOID),
        ("th32ModuleID", DWORD),
        ("cntThreads", DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase", LONG),
        ("dwFlags", DWORD),
        ("szExeFile", CHAR * MAX_PATH),
    ]

    def __init__(self):
        self.dwSize = sizeof(self)


class THREADENTRY32(Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ThreadID", DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri", DWORD),
        ("tpDeltaPri", DWORD),
        ("dwFlags", DWORD),
    ]

    def __init__(self):
        self.dwSize = sizeof(self)


class MEMORY_BASIC_INFORMATION(Structure):
    _pack_ = 4
    _fields_ = [
        ("BaseAddress", LPVOID),
        ("AllocationBase", LPVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    ]


class MEMORY_BASIC_INFORMATION64(Structure):
    _pack_ = 8
    _fields_ = [
        ("BaseAddress", ULONGLONG),
        ("AllocationBase", ULONGLONG),
        ("AllocationProtect", DWORD),
        ("__alignment1", DWORD),
        ("RegionSize", ULONGLONG),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
        ("__alignment2", DWORD),
    ]


class FLOATING_SAVE_AREA(Structure):
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Spare0", DWORD),
    ]


class CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
    ]


class EXCEPTION_DEBUG_INFO(Structure):
    EXCEPTION_MAXIMUM_PARAMETERS = 15
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", LPVOID),
        ("ExceptionAddress", PVOID),
        ("NumberParameters", DWORD),
        ("ExceptionInformation", LPVOID * 15),
        ("dwFirstChance", DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("hThread", HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
    ]


class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", HANDLE),
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("lpBaseOfImage", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]


class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [("dwExitCode", DWORD)]


class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [("dwExitCode", DWORD)]


class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", HANDLE),
        ("lpBaseOfDll", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [("lpBaseOfDll", LPVOID)]


class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ("lpDebugStringData", LPSTR),
        ("fUnicode", WORD),
        ("nDebugStringLength", WORD),
    ]


class RIP_INFO(Structure):
    _fields_ = [("dwError", DWORD), ("dwType", DWORD)]


class Union(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]


class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", Union),
    ]


class CLIENT_ID(Structure):
    _fields_ = [("UniqueProcess", HANDLE), ("UniqueThread", HANDLE)]


class THREAD_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus", DWORD),
        ("TebBaseAddress", LPVOID),
        ("ClientId", CLIENT_ID),
        ("AffinityMask", ULONG_PTR),
        ("Priority", LONG),
        ("BasePriority", LONG),
    ]


CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = BOOL
DuplicateHandle = kernel32.DuplicateHandle
DuplicateHandle.argtypes = [
    HANDLE,
    HANDLE,
    HANDLE,
    POINTER(HANDLE),
    DWORD,
    BOOL,
    DWORD,
]
DuplicateHandle.restype = BOOL
GetLastError = kernel32.GetLastError
GetLastError.argtypes = []
GetLastError.restype = DWORD
WaitForSingleObject = kernel32.WaitForSingleObject

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [DWORD, BOOL, DWORD]
OpenProcess.restype = HANDLE
TerminateProcess = kernel32.TerminateProcess
TerminateProcess.argtypes = [HANDLE, UINT]
TerminateProcess.restype = BOOL

OpenThread = kernel32.OpenThread
OpenThread.argtypes = [DWORD, BOOL, DWORD]
OpenThread.restype = HANDLE
GetThreadId = kernel32.GetThreadId
GetThreadId.argtypes = [HANDLE]
GetThreadId.restype = DWORD
ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = [HANDLE]
ResumeThread.restype = DWORD
SuspendThread = kernel32.SuspendThread
SuspendThread.argtypes = [HANDLE]
SuspendThread.restype = DWORD
CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = [
    HANDLE,
    LPVOID,
    SIZE_T,
    LPVOID,
    LPVOID,
    DWORD,
    POINTER(DWORD),
]
CreateRemoteThread.restype = HANDLE
TerminateThread = kernel32.TerminateThread
TerminateThread.argtypes = [HANDLE, DWORD]
TerminateThread.restype = BOOL
GetExitCodeThread = kernel32.GetExitCodeThread
GetExitCodeThread.argtypes = [HANDLE, POINTER(DWORD)]
GetExitCodeThread.restype = BOOL
GetExitCodeProcess = kernel32.GetExitCodeProcess
GetExitCodeProcess.argtypes = [HANDLE, POINTER(DWORD)]
GetExitCodeProcess.restype = BOOL
GetThreadContext = kernel32.GetThreadContext
GetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT)]
GetThreadContext.restype = BOOL
SetThreadContext = kernel32.SetThreadContext
SetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT)]
SetThreadContext.restype = BOOL

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
VirtualAllocEx.restype = LPVOID
VirtualFreeEx = kernel32.VirtualFreeEx
VirtualFreeEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD]
VirtualFreeEx.restype = BOOL
VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, POINTER(DWORD)]
VirtualProtectEx.restype = BOOL
VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T]
VirtualQueryEx.restype = SIZE_T
ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
ReadProcessMemory.restype = BOOL
WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
FlushInstructionCache = kernel32.FlushInstructionCache
FlushInstructionCache.argtypes = [HANDLE, LPVOID, SIZE_T]
FlushInstructionCache.restype = BOOL

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
CreateToolhelp32Snapshot.restype = HANDLE
Module32First = kernel32.Module32First
Module32First.argtypes = [HANDLE, POINTER(MODULEENTRY32)]
Module32First.restype = BOOL
Module32Next = kernel32.Module32Next
Module32Next.argtypes = [HANDLE, POINTER(MODULEENTRY32)]
Module32Next.restype = BOOL
Process32First = kernel32.Process32First
Process32First.argtypes = [HANDLE, POINTER(PROCESSENTRY32)]
Process32First.restype = BOOL
Process32Next = kernel32.Process32Next
Process32Next.argtypes = [HANDLE, POINTER(PROCESSENTRY32)]
Process32Next.restype = BOOL
Thread32First = kernel32.Thread32First
Thread32First.argtypes = [HANDLE, POINTER(THREADENTRY32)]
Thread32First.restype = BOOL
Thread32Next = kernel32.Thread32Next
Thread32Next.argtypes = [HANDLE, POINTER(THREADENTRY32)]
Thread32Next.restype = BOOL

DebugSetProcessKillOnExit = kernel32.DebugSetProcessKillOnExit
DebugSetProcessKillOnExit.argtypes = [BOOL]
DebugSetProcessKillOnExit.restype = BOOL
DebugActiveProcess = kernel32.DebugActiveProcess
DebugActiveProcess.argtypes = [DWORD]
DebugActiveProcess.restype = BOOL
DebugActiveProcessStop = kernel32.DebugActiveProcessStop
DebugActiveProcessStop.argtypes = [DWORD]
DebugActiveProcessStop.restype = BOOL
WaitForDebugEvent = kernel32.WaitForDebugEvent
WaitForDebugEvent.argtypes = [POINTER(DEBUG_EVENT), DWORD]
WaitForDebugEvent.restype = BOOL
ContinueDebugEvent = kernel32.ContinueDebugEvent
ContinueDebugEvent.argtypes = [DWORD, DWORD, DWORD]
ContinueDebugEvent.restype = BOOL

FormatMessageW = kernel32.FormatMessageW
FormatMessageW.argtypes = [
    DWORD,
    LPVOID,
    DWORD,
    DWORD,
    LPWSTR,
    DWORD,
]  # How do we specify va_list ?
FormatMessageW.restype = DWORD
LoadLibraryA = kernel32.LoadLibraryA
LoadLibraryA.argtypes = [LPSTR]
LoadLibraryA.restype = HMODULE
LoadLibraryW = kernel32.LoadLibraryW
LoadLibraryW.argtypes = [LPWSTR]
LoadLibraryW.restype = HMODULE
GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = [HMODULE, LPSTR]
GetProcAddress.restype = LPVOID
GetModuleHandleA = kernel32.GetModuleHandleA
GetModuleHandleA.argtypes = [LPSTR]
GetModuleHandleA.restype = HMODULE
GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.argtypes = [LPWSTR]
GetModuleHandleW.restype = HMODULE

NtQueryInformationThread = ntdll.NtQueryInformationThread
NtQueryInformationThread.argtypes = [HANDLE, DWORD, PVOID, ULONG, POINTER(ULONG)]
NtQueryInformationThread.restype = NTSTATUS

def FormatMessage(error):
    """Format a Win32 error code to the corresponding message. (See MSDN)"""
    size = 256
    while size < 0x10000:  # 0x10000 is the constant choosed in C# standard lib.
        buffer = (WCHAR * size)()
        result = _FormatMessageW(
            0x200 | 0x1000 | 0x2000, None, error, 0, byref(buffer), size, None
        )
        if result > 0:
            return buffer[: result - 2]
        if _GetLastError() != 0x7A:  # ERROR_INSUFFICIENT_BUFFER
            break
    return "Unknown error"


class Win32Exception(RuntimeError):
    """Exception class for Win32 runtime errors."""

    def __init__(self, error=None, message=None):
        self.error = error or _GetLastError()
        self.msg = message or _FormatMessage(self.error)

    def __str__(self):
        return "%s (0x%08x)" % (self.msg, self.error)

    def __repr__(self):
        return "Win32Exception(%s)" % str(self)