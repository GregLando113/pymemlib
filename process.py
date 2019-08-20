from . import win32
from . import utils
from ctypes import (
    byref
)
import struct
from ctypes.wintypes import *
from .thread import ProcessThread

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

    def __init__(self, pid, right=win32.PROCESS_ALL_ACCESS):
        self.id = pid
        self.handle = win32.OpenProcess(right, False, pid)
        if not self.handle:
            raise Win32Exception()

    def __del__(self):
        win32.CloseHandle(self.handle)

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
        success = win32.TerminateProcess(self.handle, code)
        if not success:
            raise win32.Win32Exception()

    def join(self, timeout=win32.INFINITE):
        """Wait until the Process terminates and Returns exit code"""
        reason = win32.WaitForSingleObject(self.handle, timeout)
        if reason != _WAIT_OBJECT_0:
            raise RuntimeError("Thread has been terminated prematurely.")
        code = DWORD()
        success = win32.GetExitCodeProcess(self.handle, byref(code))
        if not success:
            raise win32.Win32Exception()
        return code.value

    def flush(self, addr=None, size=0):
        """Flush the instruction cache for the process"""
        win32.FlushInstructionCache(self.handle, addr, size)

    def write(self, addr, *data):
        """Writes in remote process at the given address the data."""
        binary = b"".join(data)
        success = win32.WriteProcessMemory(self.handle, addr, binary, len(binary), None)
        if not success:
            raise win32.Win32Exception()

    def read(self, addr, format="I"):
        """Reads in remote process at given address and return the given format."""
        size = struct.calcsize(format)
        buffer = utils.create_buffer(size)
        success = win32.ReadProcessMemory(self.handle, addr, byref(buffer), size, None)
        if not success:
            raise win32.Win32Exception()
        t = struct.unpack(format, buffer)
        if len(t) == 1:
            return t[0]
        return t

    def mmap(self, size, addr=None):
        """Allocates memory from the unmanaged memory of the process by using the specified number of bytes."""
        right = 0x40  # PAGE_EXECUTE_READWRITE
        flags = 0x1000 | 0x2000  # MEM_COMMIT | MEM_RESERVE
        memory = win32.VirtualAllocEx(self.handle, addr, size, flags, right)
        if not memory:
            raise win32.Win32Exception()
        return memory

    def unmap(self, addr):
        """Releases memory previously allocated from the unmanaged memory of the process."""
        flags = 0x8000  # MEM_RELEASE
        win32.VirtualFreeEx(self.handle, addr, 0, flags)

    def mapshared(self, size):
        return SharedMemBuffer(self, size)

    @property
    def threads(self):
        """Returns the ProcessThread's list of the process."""
        buffer = win32.THREADENTRY32()
        snap = win32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, self.id)
        if not snap:
            raise win32.Win32Exception()

        _threads = list()
        while win32.Thread32Next(snap, byref(buffer)):
            if buffer.th32OwnerProcessID == self.id:
                _threads.append(ProcessThread(buffer.th32ThreadID, self))

        win32.CloseHandle(snap)
        return _threads

    @property
    def modules(self):
        """Returns the ProcessModule's list of the process."""
        buffer = win32.MODULEENTRY32()
        snapshot = win32.CreateToolhelp32Snapshot(
            _TH32CS_SNAPMODULE | _TH32CS_SNAPMODULE32, self.id
        )
        if not snapshot:
            raise Win32Exception()

        _modules = list()
        while win32.Module32Next(snapshot, byref(buffer)):
            _modules.append(ProcessModule.from_MODULEENTRY32(buffer, self))

        win32.CloseHandle(snapshot)
        return _modules

    def module(self, name=None):
        """Return a ProcessModule's instance of a given module's name."""
        buffer = win32.MODULEENTRY32()
        snapshot = win32.CreateToolhelp32Snapshot(
            win32.TH32CS_SNAPMODULE | win32.TH32CS_SNAPMODULE32, self.id
        )
        if not snapshot:
            raise win32.Win32Exception()

        if name == None:
            rv = win32.Module32First(
                snapshot, byref(buffer)
            )  # can this even fail if we were able to open the snapshot ?
            win32.CloseHandle(snapshot)
            return ProcessModule.from_MODULEENTRY32(buffer, self)

        name = name.encode("ascii")
        while win32.Module32Next(snapshot, byref(buffer)):
            if buffer.szModule == name:
                win32.CloseHandle(snapshot)
                return ProcessModule.from_MODULEENTRY32(buffer, self)

        raise RuntimeError("No process module with the given name was found.")

    def is_x64(self):
        m = self.module()
        new_header_offset = self.read(m.base + 0x3C, "H")
        machine = self.read(m.base + new_header_offset + 0x4, "H")
        return machine == 0x8664

    def page_info(self, addr):
        """Returns (size, access right) about a range of pages in the virtual address space of a process."""
        if not win32.PROCESS_IS_64_BITS:
            buffer = win32.MEMORY_BASIC_INFORMATION()
        else:
            buffer = win32.MEMORY_BASIC_INFORMATION64()
        _VirtualQueryEx(self.handle, addr, byref(buffer), sizeof(buffer))
        return buffer.RegionSize, buffer.Protect

    def spawn_thread(self, entry, param=None):
        """Spawns a thread in a suspended state and returns his ProcessThread."""
        id = DWORD()
        handle = win32.CreateRemoteThread(self.handle, 0, 0, entry, param, 4, byref(id))
        if not handle:
            raise win32.Win32Exception()
        return ProcessThread(id, self, handle)

    @classmethod
    def from_name(cls, name):
        """Creates a Process from his name."""
        processes = GetProcesses(name)
        if not len(processes):
            raise RuntimeError("No process with the given name was found.")
        return processes[0]


def GetProcesses(name, right=win32.PROCESS_ALL_ACCESS):
    """Returns a list of Process that have the give name."""
    name = name.encode("ascii")
    entries = list()

    buffer = win32.PROCESSENTRY32()
    snapshot = win32.CreateToolhelp32Snapshot(win32.TH32CS_SNAPPROCESS, 0)
    if not snapshot:
        raise win32.Win32Exception()

    while win32.Process32Next(snapshot, byref(buffer)):
        if buffer.szExeFile == name:
            entries.append(Process(buffer.th32ProcessID, right))

    win32.CloseHandle(snapshot)
    return entries