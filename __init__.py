from ctypes import Structure, Array, Union, POINTER, sizeof, byref
from ctypes.wintypes import *

from contextlib import suppress

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
_PROCESS_IS_64_BITS = sys.maxsize > 2 ** 32

# standard access rights
_DELETE = 0x00010000
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_SYNCHRONIZE = 0x00100000
_STANDARD_RIGHTS_ALL = 0x001F0000

_PROCESS_TERMINATE = 0x0001
_PROCESS_CREATE_THREAD = 0x0002
_PROCESS_SET_SESSIONID = 0x0004
_PROCESS_VM_OPERATION = 0x0008
_PROCESS_VM_READ = 0x0010
_PROCESS_VM_WRITE = 0x0020
_PROCESS_DUP_HANDLER = 0x0040
_PROCESS_CREATE_PROCESS = 0x0080
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_SET_INFORMATION = 0x0200
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_SUSPEN_RESUME = 0x0800
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_PROCESS_SET_LIMITED_INFORMATION = 0x2000
_PROCESS_ALL_ACCESS = _STANDARD_RIGHTS_ALL | 0xFFFF

_THREAD_TERMINATE = 0x0001
_THREAD_SUSPEND_RESUME = 0x0002
_THREAD_GET_CONTEXT = 0x0004
_THREAD_SET_CONTEXT = 0x0008
_THREAD_QUERY_INFORMATION = 0x0010
_THREAD_SET_INFORMATION = 0x0020
_THREAD_SET_THREAD_TOKEN = 0x0080
_THREAD_IMPERSONATE = 0x0100
_THREAD_DIRECT_IMPERSONATION = 0x0200
_THREAD_SET_LIMITED_INFORMATION = 0x0400
_THREAD_QUERY_LIMITED_INFORMATION = 0x0800
_THREAD_RESUME = 0x1000
_THREAD_ALL_ACCESS = _STANDARD_RIGHTS_ALL | 0xFFFF

_TH32CS_SNAPHEAPLIST = 0x00000001
_TH32CS_SNAPPROCESS = 0x00000002
_TH32CS_SNAPTHREAD = 0x00000004
_TH32CS_SNAPMODULE = 0x00000008
_TH32CS_SNAPMODULE32 = 0x00000010
_TH32CS_SNAPALL = 0x000000FF
_TH32CS_INHERIT = 0x80000000

_CONTEXT_CONTROL = 0x00010001  # SS:SP, CS:IP, FLAGS, BP
_CONTEXT_INTEGER = 0x00010002  # AX, BX, CX, DX, SI, DI
_CONTEXT_SEGMENTS = 0x00010004  # DS, ES, FS, GS
_CONTEXT_FLOATING_POINT = 0x00010008  # 387 state
_CONTEXT_DEBUG_REGISTERS = 0x00010010  # DB 0-3,6,7
_CONTEXT_EXTENDED_REGISTERS = 0x00010020  # cpu specific extensions
_CONTEXT_FULL = _CONTEXT_CONTROL | _CONTEXT_INTEGER | _CONTEXT_SEGMENTS

_EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002
_EXCEPTION_BREAKPOINT = 0x80000003
_EXCEPTION_SINGLE_STEP = 0x80000004
_EXCEPTION_ACCESS_VIOLATION = 0xC0000005
_EXCEPTION_IN_PAGE_ERROR = 0xC0000006
_EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D
_EXCEPTION_NONCONTINUABLE_EXCEPTION = 0xC0000025
_EXCEPTION_INVALID_DISPOSITION = 0xC0000026
_EXCEPTION_ARRAY_BOUNDS_EXCEEDED = 0xC000008C
_EXCEPTION_FLT_DENORMAL_OPERAND = 0xC000008D
_EXCEPTION_FLT_DIVIDE_BY_ZERO = 0xC000008E
_EXCEPTION_FLT_INEXACT_RESULT = 0xC000008F
_EXCEPTION_FLT_INVALID_OPERATION = 0xC0000090
_EXCEPTION_FLT_OVERFLOW = 0xC0000091
_EXCEPTION_FLT_STACK_CHECK = 0xC0000092
_EXCEPTION_FLT_UNDERFLOW = 0xC0000093
_EXCEPTION_INT_DIVIDE_BY_ZERO = 0xC0000094
_EXCEPTION_INT_OVERFLOW = 0xC0000095
_EXCEPTION_PRIV_INSTRUCTION = 0xC0000096
_EXCEPTION_STACK_OVERFLOW = 0xC00000FD

_ThreadBasicInformation = 0
_ThreadTimes = 1
_ThreadPriority = 2
_ThreadBasePriority = 3
_ThreadAffinityMask = 4
_ThreadImpersonationToken = 5
_ThreadDescriptorTableEntry = 6
_ThreadEnableAlignmentFaultFixup = 7
_ThreadEventPair = 8
_ThreadQuerySetWin32StartAddress = 9
_ThreadZeroTlsCell = 10
_ThreadPerformanceCount = 11
_ThreadAmILastThread = 12
_ThreadIdealProcessor = 13
_ThreadPriorityBoost = 14
_ThreadSetTlsArrayAddress = 15
_ThreadIsIoPending = 16
_ThreadHideFromDebugger = 17

_IGNORE = 0
_INFINITE = 0xFFFFFFFF

_WAIT_OBJECT_0 = 0x00000000
_WAIT_ABANDONED = 0x00000080
_WAIT_TIMEOUT = 0x00000102
_WAIT_FAILED = 0xFFFFFFFF

_MAX_PATH = 260

_EXCEPTION_DEBUG_EVENT = 1
_CREATE_THREAD_DEBUG_EVENT = 2
_CREATE_PROCESS_DEBUG_EVENT = 3
_EXIT_THREAD_DEBUG_EVENT = 4
_EXIT_PROCESS_DEBUG_EVENT = 5
_LOAD_DLL_DEBUG_EVENT = 6
_UNLOAD_DLL_DEBUG_EVENT = 7
_OUTPUT_DEBUG_STRING_EVENT = 8
_RIP_EVENT = 9

_DBG_CONTINUE = 0x00010002
_DBG_EXCEPTION_NOT_HANDLED = 0x80010001

# Make kernel32 independant of windll which may be unpredictable.
_kernel32 = ctypes.WinDLL("kernel32.dll")
_ntdll = ctypes.WinDLL("ntdll.dll")


class _MODULEENTRY32(Structure):
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
        ("szExePath", CHAR * _MAX_PATH),
    ]

    def __init__(self):
        self.dwSize = sizeof(self)


class _PROCESSENTRY32(Structure):
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
        ("szExeFile", CHAR * _MAX_PATH),
    ]

    def __init__(self):
        self.dwSize = sizeof(self)


class _THREADENTRY32(Structure):
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


class _MEMORY_BASIC_INFORMATION(Structure):
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


class _MEMORY_BASIC_INFORMATION64(Structure):
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


class _FLOATING_SAVE_AREA(Structure):
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


class _CONTEXT(Structure):
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", _FLOATING_SAVE_AREA),
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


class _EXCEPTION_DEBUG_INFO(Structure):
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


class _CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ("hThread", HANDLE),
        ("lpThreadLocalBase", LPVOID),
        ("lpStartAddress", LPVOID),
    ]


class _CREATE_PROCESS_DEBUG_INFO(Structure):
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


class _EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [("dwExitCode", DWORD)]


class _EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [("dwExitCode", DWORD)]


class _LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ("hFile", HANDLE),
        ("lpBaseOfDll", LPVOID),
        ("dwDebugInfoFileOffset", DWORD),
        ("nDebugInfoSize", DWORD),
        ("lpImageName", LPVOID),
        ("fUnicode", WORD),
    ]


class _UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [("lpBaseOfDll", LPVOID)]


class _OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ("lpDebugStringData", LPSTR),
        ("fUnicode", WORD),
        ("nDebugStringLength", WORD),
    ]


class _RIP_INFO(Structure):
    _fields_ = [("dwError", DWORD), ("dwType", DWORD)]


class _Union(ctypes.Union):
    _fields_ = [
        ("Exception", _EXCEPTION_DEBUG_INFO),
        ("CreateThread", _CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", _CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", _EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", _EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", _LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", _UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", _OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", _RIP_INFO),
    ]


class _DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", _Union),
    ]


class _CLIENT_ID(Structure):
    _fields_ = [("UniqueProcess", HANDLE), ("UniqueThread", HANDLE)]


class _THREAD_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus", DWORD),
        ("TebBaseAddress", LPVOID),
        ("ClientId", _CLIENT_ID),
        ("AffinityMask", ULONG_PTR),
        ("Priority", LONG),
        ("BasePriority", LONG),
    ]


_CloseHandle = _kernel32.CloseHandle
_CloseHandle.argtypes = [HANDLE]
_CloseHandle.restype = BOOL
_DuplicateHandle = _kernel32.DuplicateHandle
_DuplicateHandle.argtypes = [
    HANDLE,
    HANDLE,
    HANDLE,
    POINTER(HANDLE),
    DWORD,
    BOOL,
    DWORD,
]
_DuplicateHandle.restype = BOOL
_GetLastError = _kernel32.GetLastError
_GetLastError.argtypes = []
_GetLastError.restype = DWORD
_WaitForSingleObject = _kernel32.WaitForSingleObject

_OpenProcess = _kernel32.OpenProcess
_OpenProcess.argtypes = [DWORD, BOOL, DWORD]
_OpenProcess.restype = HANDLE
_TerminateProcess = _kernel32.TerminateProcess
_TerminateProcess.argtypes = [HANDLE, UINT]
_TerminateProcess.restype = BOOL

_OpenThread = _kernel32.OpenThread
_OpenThread.argtypes = [DWORD, BOOL, DWORD]
_OpenThread.restype = HANDLE
_GetThreadId = _kernel32.GetThreadId
_GetThreadId.argtypes = [HANDLE]
_GetThreadId.restype = DWORD
_ResumeThread = _kernel32.ResumeThread
_ResumeThread.argtypes = [HANDLE]
_ResumeThread.restype = DWORD
_SuspendThread = _kernel32.SuspendThread
_SuspendThread.argtypes = [HANDLE]
_SuspendThread.restype = DWORD
_CreateRemoteThread = _kernel32.CreateRemoteThread
_CreateRemoteThread.argtypes = [
    HANDLE,
    LPVOID,
    SIZE_T,
    LPVOID,
    LPVOID,
    DWORD,
    POINTER(DWORD),
]
_CreateRemoteThread.restype = HANDLE
_TerminateThread = _kernel32.TerminateThread
_TerminateThread.argtypes = [HANDLE, DWORD]
_TerminateThread.restype = BOOL
_GetExitCodeThread = _kernel32.GetExitCodeThread
_GetExitCodeThread.argtypes = [HANDLE, POINTER(DWORD)]
_GetExitCodeThread.restype = BOOL
_GetExitCodeProcess = _kernel32.GetExitCodeProcess
_GetExitCodeProcess.argtypes = [HANDLE, POINTER(DWORD)]
_GetExitCodeProcess.restype = BOOL
_GetThreadContext = _kernel32.GetThreadContext
_GetThreadContext.argtypes = [HANDLE, POINTER(_CONTEXT)]
_GetThreadContext.restype = BOOL
_SetThreadContext = _kernel32.SetThreadContext
_SetThreadContext.argtypes = [HANDLE, POINTER(_CONTEXT)]
_SetThreadContext.restype = BOOL

_VirtualAllocEx = _kernel32.VirtualAllocEx
_VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
_VirtualAllocEx.restype = LPVOID
_VirtualFreeEx = _kernel32.VirtualFreeEx
_VirtualFreeEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD]
_VirtualFreeEx.restype = BOOL
_VirtualProtectEx = _kernel32.VirtualProtectEx
_VirtualProtectEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, POINTER(DWORD)]
_VirtualProtectEx.restype = BOOL
_VirtualQueryEx = _kernel32.VirtualQueryEx
_VirtualQueryEx.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T]
_VirtualQueryEx.restype = SIZE_T
_ReadProcessMemory = _kernel32.ReadProcessMemory
_ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
_ReadProcessMemory.restype = BOOL
_WriteProcessMemory = _kernel32.WriteProcessMemory
_WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)]
_FlushInstructionCache = _kernel32.FlushInstructionCache
_FlushInstructionCache.argtypes = [HANDLE, LPVOID, SIZE_T]
_FlushInstructionCache.restype = BOOL

_CreateToolhelp32Snapshot = _kernel32.CreateToolhelp32Snapshot
_CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
_CreateToolhelp32Snapshot.restype = HANDLE
_Module32First = _kernel32.Module32First
_Module32First.argtypes = [HANDLE, POINTER(_MODULEENTRY32)]
_Module32First.restype = BOOL
_Module32Next = _kernel32.Module32Next
_Module32Next.argtypes = [HANDLE, POINTER(_MODULEENTRY32)]
_Module32Next.restype = BOOL
_Process32First = _kernel32.Process32First
_Process32First.argtypes = [HANDLE, POINTER(_PROCESSENTRY32)]
_Process32First.restype = BOOL
_Process32Next = _kernel32.Process32Next
_Process32Next.argtypes = [HANDLE, POINTER(_PROCESSENTRY32)]
_Process32Next.restype = BOOL
_Thread32First = _kernel32.Thread32First
_Thread32First.argtypes = [HANDLE, POINTER(_THREADENTRY32)]
_Thread32First.restype = BOOL
_Thread32Next = _kernel32.Thread32Next
_Thread32Next.argtypes = [HANDLE, POINTER(_THREADENTRY32)]
_Thread32Next.restype = BOOL

_DebugSetProcessKillOnExit = _kernel32.DebugSetProcessKillOnExit
_DebugSetProcessKillOnExit.argtypes = [BOOL]
_DebugSetProcessKillOnExit.restype = BOOL
_DebugActiveProcess = _kernel32.DebugActiveProcess
_DebugActiveProcess.argtypes = [DWORD]
_DebugActiveProcess.restype = BOOL
_DebugActiveProcessStop = _kernel32.DebugActiveProcessStop
_DebugActiveProcessStop.argtypes = [DWORD]
_DebugActiveProcessStop.restype = BOOL
_WaitForDebugEvent = _kernel32.WaitForDebugEvent
_WaitForDebugEvent.argtypes = [POINTER(_DEBUG_EVENT), DWORD]
_WaitForDebugEvent.restype = BOOL
_ContinueDebugEvent = _kernel32.ContinueDebugEvent
_ContinueDebugEvent.argtypes = [DWORD, DWORD, DWORD]
_ContinueDebugEvent.restype = BOOL

_FormatMessageW = _kernel32.FormatMessageW
_FormatMessageW.argtypes = [
    DWORD,
    LPVOID,
    DWORD,
    DWORD,
    LPWSTR,
    DWORD,
]  # How do we specify va_list ?
_FormatMessageW.restype = DWORD
_LoadLibraryA = _kernel32.LoadLibraryA
_LoadLibraryA.argtypes = [LPSTR]
_LoadLibraryA.restype = HMODULE
_LoadLibraryW = _kernel32.LoadLibraryW
_LoadLibraryW.argtypes = [LPWSTR]
_LoadLibraryW.restype = HMODULE
_GetProcAddress = _kernel32.GetProcAddress
_GetProcAddress.argtypes = [HMODULE, LPSTR]
_GetProcAddress.restype = LPVOID
_GetModuleHandleA = _kernel32.GetModuleHandleA
_GetModuleHandleA.argtypes = [LPSTR]
_GetModuleHandleA.restype = HMODULE
_GetModuleHandleW = _kernel32.GetModuleHandleW
_GetModuleHandleW.argtypes = [LPWSTR]
_GetModuleHandleW.restype = HMODULE

_NtQueryInformationThread = _ntdll.NtQueryInformationThread
_NtQueryInformationThread.argtypes = [HANDLE, DWORD, PVOID, ULONG, POINTER(ULONG)]
_NtQueryInformationThread.restype = NTSTATUS


def _create_buffer(size):
    """Create a ctypes buffer of a given size."""
    buftype = CHAR * size
    return buftype()


def _get_ctype_string(type):
    """Returns the type string to be used with unpack/pack"""
    from ctypes import _SimpleCData

    if issubclass(type, _SimpleCData):
        return type._type_
    elif issubclass(type, Array):
        elem_type = _get_ctype_string(type._type_)
        return "%d%s" % (type._length_, elem_type)
    elif issubclass(type, Structure):
        return "".join(_get_ctype_string(t) for n, t in type._fields_)
    else:
        raise RuntimeError("The type %s is not supported" % str(type))


def _FormatMessage(error):
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
    return "Unknow error"


class Win32Exception(RuntimeError):
    """Exception class for Win32 runtime errors."""

    def __init__(self, error=None, message=None):
        self.error = error or _GetLastError()
        self.msg = message or _FormatMessage(self.error)

    def __str__(self):
        return "%s (0x%08x)" % (self.msg, self.error)

    def __repr__(self):
        return "Win32Exception(%s)" % str(self)


class ProcessScanner(object):
    """
    Class used to scan remote process's code section.
    """

    def __init__(self, proc):
        self.proc = proc
        self.module = proc.module()
        if not self.module:
            raise RuntimeError("Couldn't find default module")
        # Very hacky but that will do it for now
        self.base = self.module.base + 0x1000
        size, _ = proc.page_info(self.base)
        self.buffer, = proc.read(self.base, "%ds" % size)

    def find(self, pattern, offset=0):
        """Returns address of the pattern if found."""
        match = self.buffer.find(pattern)
        if not match:
            raise RuntimeError("Couldn't find the pattern.")
        return self.base + match + offset

    def __repr__(self):
        return "<Scanner 0x%08x for Process %d>" % (id(self), self.proc.id)


class ProcessModule(object):
    """
    A Win32 process module object.
    
    Properties:
        - handle
        - pid
        - name
        - base
        - size
        - file
    """

    def __init__(self, handle, process):
        self.handle = handle
        self.pid = process.id

        # make sure all properties are initialized
        self.name = None
        self.base = None
        self.size = None
        self.file = None

    def __eq__(self, other):
        return (self.handle == other.handle) and (self.pid == other.pid)

    def __str__(self):
        return "0x%08x %s" % (self.base, self.name)

    def __repr__(self):
        return "<ProcessModule %s in Process %d>" % (str(self), self.pid)

    @classmethod
    def from_MODULEENTRY32(cls, module, process):
        mod = ProcessModule(module.hModule, process)
        mod.name = module.szModule.decode("ascii").lower()
        mod.base = module.modBaseAddr
        mod.size = module.modBaseSize
        mod.file = module.szExePath.decode("ascii")
        return mod


class ProcessThread(object):
    """
    A Win32 process thread object.

    Properties:
        - id
        - pid
        - handle
        - alive
        - running
    """

    def __init__(self, id, process, handle=None):
        self.id = id
        self.pid = process.id

        self.handle = handle or _OpenThread(_THREAD_ALL_ACCESS, False, id)
        if not self.handle:
            raise Win32Exception()

    def __del__(self):
        _CloseHandle(self.handle)

    def __eq__(self, other):
        return self.id == other.id

    def __repr__(self):
        return "<ProcessThread %d in Process %d>" % (self.id, self.pid)

    def kill(self, code=0):
        """Terminates the Thread with the given exit code."""
        success = _TerminateThread(self.handle, code)
        if not success:
            raise Win32Exception()

    @property
    def alive(self):
        """Checks if the thread is still executing."""
        code = DWORD()
        success = _GetExitCodeThread(self.handle, byref(code))
        if not success:
            raise Win32Exception()
        return code.value == 259  # STILL_ACTIVE = 259

    def resume(self):
        """Resumes the thread."""
        count = _ResumeThread(self.handle)
        if count == 0xFFFFFFFF:
            raise Win32Exception()

    def suspend(self):
        """Suspends the thread."""
        count = _SuspendThread(self.handle)
        if count == 0xFFFFFFFF:
            raise Win32Exception()

    def join(self, timeout=_INFINITE):
        """Waits until the thread exit and returns the exit code."""
        reason = _WaitForSingleObject(self.handle, timeout)
        if reason != _WAIT_OBJECT_0:
            raise RuntimeError("Thread has been terminated prematurely.")
        code = DWORD()
        success = _GetExitCodeThread(self.handle, byref(code))
        if not success:
            raise Win32Exception()
        return code.value

    def context(self, flags=_CONTEXT_FULL):
        """Retrieves the context of the ProcessThread."""
        context = _CONTEXT()
        context.ContextFlags = flags
        success = _GetThreadContext(self.handle, byref(context))
        if not success:
            raise Win32Exception()
        return context

    def set_context(self, context):
        """Sets the context for the ProcessThread."""
        success = _SetThreadContext(self.handle, byref(context))
        if not success:
            raise Win32Exception()

    @property
    def teb(self):
        """Returns the address of the thread's information/environment block"""
        info = _THREAD_BASIC_INFORMATION()
        ntstatus = _NtQueryInformationThread(
            self.handle, _ThreadBasicInformation, byref(info), sizeof(info), None
        )
        # Need confirmation, but WinDll default returns type is int and
        # NTSUCCESS are positive signed 32 bytes integers [0 - 0x7fffffff]
        if ntstatus < 0:
            raise Win32Exception()
        return info.TebBaseAddress


class Hook(object):
    """
    Callable object that can contains information about the calling convention
    and the types of his params. Usefull to hook function compiled in C.

    e.g.
    @Hook.stdcall(DWORD)
    def OnSleep(dwMilliseconds):
        print(f'Sleep for {dwMilliseconds} ms')
    OnSleep(25) # prints 'Sleep for 25 ms'

    Note: The function can also be a method.
    e.g.
    class WatchProcess(object):
        def __init__(self, name):
            self.name = name

        @Hook.stdcall(DWORD)
        def OnSleep(self, dwMilliseconds):
            print(f'Process {self.name} Sleep for {dwMilliseconds} ms')

    p1 = WatchProcess('Notepad')
    s1 = p1.OnSleep
    s1(10) # prints 'Process Notepad Sleep for 10 ms'

    p2 = WatchProcess('Vim')
    s2 = p2.OnSleep
    s2(20) # prints 'Process Vim Sleep for 20 ms'
    """

    _stdcall = 1
    _fastcall = 2
    _thiscall = 3

    def __init__(self, callback, callconv, argtypes):
        self.callback = callback
        self.callconv = callconv
        self.argtypes = argtypes

        self.argstr = "".join(_get_ctype_string(arg) for arg in argtypes)
        self.extargs = []

    def __hash__(self):
        return hash(self.callback)

    def __repr__(self):
        return repr(self.callback)

    def __str__(self):
        return str(self.callback)

    def __get__(self, inst, parent):
        hook = self.clone()
        hook.extargs = [inst]
        return hook

    def __call__(self, *args, **kw):
        return self.callback(*self.extargs, *args, **kw)

    def clone(self):
        return Hook(self.callback, self.callconv, self.argtypes)

    def stdcall(*argtypes):
        def wrapper(function):
            proc = Hook(function, Hook._stdcall, argtypes)
            return proc

        return wrapper

    def fastcall(*argtypes):
        def wrapper(function):
            proc = Hook(function, Hook._fastcall, argtypes)
            return proc

        return wrapper

    def thiscall(*argtypes):
        def wrapper(function):
            proc = Hook(function, Hook._thiscall, argtypes)
            return proc

        return wrapper


class ProcessHook(object):
    """
    """

    def __init__(self, proc, addr, hook):
        self.proc = proc
        self.addr = addr
        self.hook = hook
        self.inst = proc.read(addr, "s")
        self.enabled = False

    def __del__(self):
        if self.enabled:
            self.disable()

    def __repr__(self):
        return "<ProcessHook %08X in Process %d>" % (self.addr, self.proc.id)

    def enable(self):
        self.enabled = True
        self.proc.write(self.addr, b"\xCC")
        self.proc.flush(self.addr, 1)

    def disable(self):
        self.enabled = False
        self.proc.write(self.addr, self.inst)
        self.proc.flush(self.addr, 1)


class ProcessDebugger(object):
    """
    """

    def __init__(self, proc=None):
        self.hooks = dict()
        self.attached = False
        _DebugSetProcessKillOnExit(False)
        if not proc is None:
            self.attach(proc)

    def __del__(self):
        self.detach()

    def __repr__(self):
        return "<ProcessDebugger for Process %d>" % self.proc.id

    def add_hook(self, addr, hook):
        proc_hook = ProcessHook(self.proc, addr, hook)
        if addr in self.hooks:
            old_hook = self.hooks[addr]
            old_hook.disable()

        self.hooks[addr] = proc_hook
        proc_hook.enable()

    def attach(self, proc):
        if self.attached:
            raise RuntimeError("ProcessDebugger already attached")
        self.proc = proc
        if not _DebugActiveProcess(proc.id):
            raise Win32Exception()
        self.attached = True

    def detach(self):
        if not self.attached:
            return
        with suppress(Exception):
            for hook in self.hooks.values():
                hook.disable()
        _DebugActiveProcessStop(self.proc.id)
        self.attached = False

    def run(self, **kw):
        frequency = kw.pop("frequency", _INFINITE)
        while self.attached:
            self.poll(frequency)

    def poll(self, timeout=_INFINITE):
        """Poll the next event dispatch it"""
        evt = _DEBUG_EVENT()
        if not _WaitForDebugEvent(byref(evt), timeout):
            return

        if evt.dwProcessId != self.proc.id:
            _ContinueDebugEvent(
                evt.dwProcessId, evt.dwThreadId, _DBG_EXCEPTION_NOT_HANDLED
            )
            return

        continue_status = _DBG_CONTINUE
        event_code = evt.dwDebugEventCode
        thread = ProcessThread(evt.dwThreadId, self.proc)

        if event_code == _EXCEPTION_DEBUG_EVENT:
            continue_status = self._on_debug_event(thread, evt.u.Exception)
        elif event_code == _CREATE_THREAD_DEBUG_EVENT:
            self.OnCreateThreadDebugEvent(thread, evt.u.CreateThread)
        elif event_code == _CREATE_PROCESS_DEBUG_EVENT:
            self.OnCreateProcessDebugEvent(thread, evt.u.CreateProcessInfo)
        elif event_code == _EXIT_THREAD_DEBUG_EVENT:
            self.OnExitThreadDebugEvent(thread, evt.u.ExitThread)
        elif event_code == _EXIT_PROCESS_DEBUG_EVENT:
            self.exit_code = evt.u.ExitProcess.dwExitCode
            self.OnExitProcessDebugEvent(thread, evt.u.ExitProcess)
            self.detach()
        elif event_code == _LOAD_DLL_DEBUG_EVENT:
            self.OnLoadDllDebugEvent(thread, evt.u.LoadDll)
        elif event_code == _UNLOAD_DLL_DEBUG_EVENT:
            self.OnUnloadDllDebugEvent(thread, evt.u.UnloadDll)
        elif event_code == _OUTPUT_DEBUG_STRING_EVENT:
            self.OnOutputDebugStringEvent(thread, evt.u.DebugString)
        elif event_code == _RIP_EVENT:
            self.OnRipEvent(evt.u.RipInfo)

        _ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continue_status)

    def _on_single_step(self, thread, addr):
        hook = self.ss_hook
        if not hook:
            return _DBG_EXCEPTION_NOT_HANDLED

        hook.enable()
        return _DBG_CONTINUE

    def _on_breakpoint(self, thread, addr):
        proc_hook = self.hooks.get(addr, None)
        if not proc_hook:
            return _DBG_EXCEPTION_NOT_HANDLED

        proc_hook.disable()

        ctx = thread.context()
        args = list()

        hook = proc_hook.hook
        conv = hook.callconv
        argc = len(hook.argtypes)

        if (argc >= 1) and ((conv == Hook._fastcall) or (conv == Hook._thiscall)):
            args.append(ctx.Ecx)
        if (argc >= 2) and (conv == Hook._fastcall):
            args.append(ctx.Edx)

        argstr = hook.argstr[len(args) :]
        argc = argc - len(args)
        stack_args = self.proc.read(ctx.Esp + 4, argstr)
        if isinstance(stack_args, (list,tuple)):
            args.extend(stack_args)
        else:
            args.append(stack_args)

        # What should we do here ??? (We don't want to crash the remote process)
        with suppress(Exception):
            hook(*args)

        # This will enable a "single-step" breakpoint
        # We cannot reach an other breakpoint before raising Single-Step exception
        self.ss_hook = proc_hook
        ctx.Eip -= 1
        ctx.EFlags |= 0x100  # TRAP_FLAG
        thread.set_context(ctx)
        return _DBG_CONTINUE

    def _on_debug_event(self, thread, info):
        """This is internal, but if you were to overload it, return the continuation status"""
        code = info.ExceptionCode
        if info.dwFirstChance != 1:
            return _DBG_EXCEPTION_NOT_HANDLED
        addr = info.ExceptionAddress
        if code == _EXCEPTION_SINGLE_STEP:
            return self._on_single_step(thread, addr)
        if code == _EXCEPTION_BREAKPOINT:
            return self._on_breakpoint(thread, addr)
        return _DBG_EXCEPTION_NOT_HANDLED

    def OnCreateThreadDebugEvent(self, thread, info):
        """Can be overloaded to hook this event"""
        pass

    def OnCreateThreadDebugEvent(self, thread, info):
        """Can be overloaded to hook this event"""
        pass

    def OnCreateProcessDebugEvent(self, thread, info):
        """Can be overloaded to hook this event"""
        pass

    def OnExitThreadDebugEvent(self, thread, info):
        """Can be overloaded to hook this event"""
        pass

    def OnExitProcessDebugEvent(self, thread, info):
        """Can be overloaded to hook this event"""
        pass

    def OnLoadDllDebugEvent(self, thread, info):
        """Can be overloaded to hook this event"""
        pass

    def OnUnloadDllDebugEvent(self, thread, info):
        """Can be overloaded to hook this event"""
        pass

    def OnOutputDebugStringEvent(self, thread, info):
        """Can be overloaded to hook this event"""
        pass

    def OnRipEvent(self):
        """Can be overloaded to hook this event"""
        pass


class ProcessCaller(object):

    '''
      stdcall:
            push ebp
            mov ebp, esp
            mov esp, dword[esp+4]
            pop eax
            call eax
            xor eax, eax
            mov esp, ebp
            pop ebp
            ret 4   
    '''
    _stdcall_code = b"\x55\x89\xE5\x8B\x64\x24\x08\x58\xFF\xD0\x31\xC0\x89\xEC\x5D\xC2\x04\x00"
    '''
        fastcall:
            push ebp
            mov ebp, esp
            mov esp, dword[esp+4]
            pop eax
            pop ecx
            pop edx
            call eax
            xor eax, eax
            mov esp, ebp
            pop ebp
            ret 4 
    '''
    _fastcall_code = b"\x55\x89\xE5\x8B\x64\x24\x08\x58\x59\x5A\xFF\xD0\x31\xC0\x89\xEC\x5D\xC2\x04\x00"
    '''
        x64call:
            push rbp
            mov rbp, rsp
            mov rsp, rcx
            pop rax
            pop rcx
            pop rdx
            pop r8
            pop r9
            call rax
            xor rax, rax
            mov rsp, rbp
            pop rbp
            ret 
    '''
    _x64call_code = b"\x55\x48\x89\xE5\x48\x89\xCC\x58\x59\x5A\x41\x58\x41\x59\xFF\xD0\x48\x31\xC0\x48\x89\xEC\x5D\xC3"

    def __init__(self,proc,stack_size=0x100000):
        self.process = proc
        self._stdcall = proc.mmap(0x20)
        self._fastcall = proc.mmap(0x20)
        self._x64call = proc.mmap(0x20)

        proc.write(self._stdcall, ProcessCaller._stdcall_code)
        proc.write(self._fastcall, ProcessCaller._fastcall_code)
        proc.write(self._x64call, ProcessCaller._x64call_code)

        self._stack_size = stack_size
        self._stackbuffer = proc.mmap(stack_size)

    def __del__(self):
        self.process.unmap(self._stdcall)
        self.process.unmap(self._fastcall)
        self.process.unmap(self._x64call)
        self.process.unmap(self._stackbuffer)


    def x64call(self, address, *argtypes):
        def _fn(*args):
            cargs = [v(args[i]) for i, v in enumerate(argtypes)]
            data = b''.join([LPVOID(address), *cargs])
            ptr = self._stackbuffer + self._stack_size - max(len(data),0x40)
            self.process.write(ptr, data)
            self.process.spawn_thread(self._x64call, ptr).resume()
        return _fn

    def fastcall(self, address, *argtypes):
        def _fn(*args):
            cargs = [v(args[i]) for i, v in enumerate(argtypes)]
            data = b''.join([LPVOID(address), *cargs])
            ptr = self._stackbuffer + self._stack_size - max(len(data),0x10)
            self.process.write(ptr, data)
            self.process.spawn_thread(self._fastcall, ptr).resume()
        return _fn

    def stdcall(self, address, *argtypes):
        def _fn(*args):
            cargs = [v(args[i]) for i, v in enumerate(argtypes)]
            data = b''.join([LPVOID(address), *cargs])
            ptr = self._stackbuffer + self._stack_size - max(len(data),0x8)
            self.process.write(ptr, data)
            self.process.spawn_thread(self._stdcall, ptr).resume()
        return _fn


class SharedMemBuffer(object):
    def __init__(self, process, size, name=None):
        self.process = process
        self.base_local = 0
        self.base_remote = 0
        self.size = size
        self.name = name

        self.map_handle = _kernel32.CreateFileMappingW(
            -1,
            None,
            0x40,
            self.size >> 32 & 0xffffffff,
            self.size & 0xffffffff,
            self.name
        )

        if not self.map_handle:
            raise RuntimeError("File map creation failed, err ", _kernel32.GetLastError())

        self.base_local = _kernel32.MapViewOfFile(
            self.map_handle,
            0x0002 | 0x0020,
            None,
            None,
            None
        )

        if not self.base_local:
            raise RuntimeError("Local mapping failed, err ", _kernel32.GetLastError())

        baddrbuf = c_void_p()
        ntresult = _ntdll.NtMapViewOfSection(
            self.map_handle,
            self.process.handle,
            byref(baddrbuf),
            None,
            None,
            byref(c_longlong()),
            byref(c_ulong()),
            2,  # ViewUnmap(2) :  do not map into child processes
            None,
            0x40
        )

        if ntresult:
            raise RuntimeError("Remote mapping failed, err ", _kernel32.GetLastError(), ', ntstatus', ntresult)

        self.base_remote = baddrbuf.value

    def __del__(self):
        result = _ntdll.NtUnmapViewOfSection(
            self.process.handle,
            self.base_remote
        )

        if result:
            raise RuntimeError("Remote unmapping failed, err ", _kernel32.GetLastError(), ', ntstatus', result)

        if not _kernel32.MapViewOfFile(self.base_local):
            raise RuntimeError("Local unmapping failed, err ", _kernel32.GetLastError(), ', ntstatus', result)

        _kernel32.CloseHandle(self.map_handle)


class Process(object):
    """
    An object to interact with a Win32 remote process.

    Properties:
        - id
        - handle
        - name
        - threads
        - modules
    """

    def __init__(self, pid, right=_PROCESS_ALL_ACCESS):
        self.id = pid
        self.handle = _OpenProcess(right, False, pid)
        if not self.handle:
            raise Win32Exception()

    def __del__(self):
        _CloseHandle(self.handle)

    def __eq__(self, other):
        return self.id == other.id

    def __repr__(self):
        return "<Process %d, handle %d at 0x%08x>" % (self.id, self.handle, id(self))

    @property
    def name(self):
        """Returns the name of the process."""
        return self.module().name

    def kill(self, code=0):
        """Terminates the Process with the given exit code."""
        success = _TerminateProcess(self.handle, code)
        if not success:
            raise Win32Exception()

    def join(self, timeout=_INFINITE):
        """Wait until the Process terminates and Returns exit code"""
        reason = _WaitForSingleObject(self.handle, timeout)
        if reason != _WAIT_OBJECT_0:
            raise RuntimeError("Thread has been terminated prematurely.")
        code = DWORD()
        success = _GetExitCodeProcess(self.handle, byref(code))
        if not success:
            raise Win32Exception()
        return code.value

    def flush(self, addr=None, size=0):
        """Flush the instruction cache for the process"""
        _FlushInstructionCache(self.handle, addr, size)

    def write(self, addr, *data):
        """Writes in remote process at the given address the data."""
        binary = b"".join(data)
        success = _WriteProcessMemory(self.handle, addr, binary, len(binary), None)
        if not success:
            raise Win32Exception()

    def read(self, addr, format="I"):
        """Reads in remote process at given address and return the given format."""
        size = struct.calcsize(format)
        buffer = _create_buffer(size)
        success = _ReadProcessMemory(self.handle, addr, byref(buffer), size, None)
        if not success:
            raise Win32Exception()
        t = struct.unpack(format, buffer)
        if len(t) == 1:
            return t[0]
        return t

    def mmap(self, size, addr=None):
        """Allocates memory from the unmanaged memory of the process by using the specified number of bytes."""
        right = 0x40  # PAGE_EXECUTE_READWRITE
        flags = 0x1000 | 0x2000  # MEM_COMMIT | MEM_RESERVE
        memory = _VirtualAllocEx(self.handle, addr, size, flags, right)
        if not memory:
            raise Win32Exception()
        return memory

    def unmap(self, addr):
        """Releases memory previously allocated from the unmanaged memory of the process."""
        flags = 0x8000  # MEM_RELEASE
        _VirtualFreeEx(self.handle, addr, 0, flags)

    def mapshared(self, size):
        return SharedMemBuffer(self, size)

    @property
    def threads(self):
        """Returns the ProcessThread's list of the process."""
        buffer = _THREADENTRY32()
        snap = _CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, self.id)
        if not snap:
            raise Win32Exception()

        _threads = list()
        while _Thread32Next(snap, byref(buffer)):
            if buffer.th32OwnerProcessID == self.id:
                _threads.append(ProcessThread(buffer.th32ThreadID, self))

        _CloseHandle(snap)
        return _threads

    @property
    def modules(self):
        """Returns the ProcessModule's list of the process."""
        buffer = _MODULEENTRY32()
        snapshot = _CreateToolhelp32Snapshot(
            _TH32CS_SNAPMODULE | _TH32CS_SNAPMODULE32, self.id
        )
        if not snapshot:
            raise Win32Exception()

        _modules = list()
        while _Module32Next(snapshot, byref(buffer)):
            _modules.append(ProcessModule.from_MODULEENTRY32(buffer, self))

        _CloseHandle(snapshot)
        return _modules

    def module(self, name=None):
        """Return a ProcessModule's instance of a given module's name."""
        buffer = _MODULEENTRY32()
        snapshot = _CreateToolhelp32Snapshot(
            _TH32CS_SNAPMODULE | _TH32CS_SNAPMODULE32, self.id
        )
        if not snapshot:
            raise Win32Exception()

        if name == None:
            rv = _Module32First(
                snapshot, byref(buffer)
            )  # can this even fail if we were able to open the snapshot ?
            _CloseHandle(snapshot)
            return ProcessModule.from_MODULEENTRY32(buffer, self)

        name = name.encode("ascii")
        while _Module32Next(snapshot, byref(buffer)):
            if buffer.szModule == name:
                _CloseHandle(snapshot)
                return ProcessModule.from_MODULEENTRY32(buffer, self)

        raise RuntimeError("No process module with the given name was found.")

    def is_x64(self):
        m = self.module()
        new_header_offset = self.read(m.base + 0x3C, "H")
        machine = self.read(m.base + new_header_offset + 0x4, "H")
        return machine == 0x8664

    def page_info(self, addr):
        """Returns (size, access right) about a range of pages in the virtual address space of a process."""
        if not _PROCESS_IS_64_BITS:
            buffer = _MEMORY_BASIC_INFORMATION()
        else:
            buffer = _MEMORY_BASIC_INFORMATION64()
        _VirtualQueryEx(self.handle, addr, byref(buffer), sizeof(buffer))
        return buffer.RegionSize, buffer.Protect

    def spawn_thread(self, entry, param=None):
        """Spawns a thread in a suspended state and returns his ProcessThread."""
        id = DWORD()
        handle = _CreateRemoteThread(self.handle, 0, 0, entry, param, 4, byref(id))
        if not handle:
            raise Win32Exception()
        return ProcessThread(id, self, handle)

    @classmethod
    def from_name(cls, name):
        """Creates a Process from his name."""
        processes = GetProcesses(name)
        if not len(processes):
            raise RuntimeError("No process with the given name was found.")
        return processes[0]


def GetProcesses(name, right=_PROCESS_ALL_ACCESS):
    """Returns a list of Process that have the give name."""
    name = name.encode("ascii")
    entries = list()

    buffer = _PROCESSENTRY32()
    snapshot = _CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot:
        raise Win32Exception()

    while _Process32Next(snapshot, byref(buffer)):
        if buffer.szExeFile == name:
            entries.append(Process(buffer.th32ProcessID, right))

    _CloseHandle(snapshot)
    return entries

def InjectDll(proc, name):
    """Inject a dll with CreateRemoteThread in the remote process"""

    class InjectionError(RuntimeError):
        pass
        
    kernel32 = _GetModuleHandleA(b"kernel32")
    if not kernel32:
        raise Win32Exception()
    LoadLibraryEx = _GetProcAddress(kernel32, b"LoadLibraryA")
    if not LoadLibraryEx:
        raise Win32Exception()
    size = len(name) + 1
    path = proc.mmap(size)
    if not path:
        raise InjectionError('Path is null')
    proc.write(path, name.encode("ascii"), b"\0")
    thread = proc.spawn_thread(LoadLibraryEx, path)
    thread.resume()
    retval = thread.join()
    proc.unmap(path)
    return retval

def EjectDll(proc, handle):
    kernel32 = _GetModuleHandleA(b"kernel32")
    if not kernel32:
        raise Win32Exception()
    FreeLibraryEx = _GetProcAddress(kernel32, b"FreeLibraryA")
    if not FreeLibraryEx:
        raise Win32Exception()
    thread = proc.spawn_thread(FreeLibraryEx, handle)
    thread.resume()
    retval = thread.join()


