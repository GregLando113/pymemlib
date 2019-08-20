from . import win32

class SharedMemBuffer(object):
    def __init__(self, process, size, name=None):
        self.process = process
        self.base_local = 0
        self.base_remote = 0
        self.size = size
        self.name = name

        self.map_handle = win32.kernel32.CreateFileMappingW(
            -1,
            None,
            0x40,
            self.size >> 32 & 0xffffffff,
            self.size & 0xffffffff,
            self.name
        )

        if not self.map_handle:
            raise RuntimeError("File map creation failed, err ", win32.kernel32.GetLastError())

        self.base_local = win32.kernel32.MapViewOfFile(
            self.map_handle,
            0x0002 | 0x0020,
            None,
            None,
            None
        )

        if not self.base_local:
            raise RuntimeError("Local mapping failed, err ", win32.kernel32.GetLastError())

        baddrbuf = c_void_p()
        ntresult = win32.ntdll.NtMapViewOfSection(
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
            raise RuntimeError("Remote mapping failed, err ", win32.kernel32.GetLastError(), ', ntstatus', ntresult)

        self.base_remote = baddrbuf.value

    def __del__(self):
        result = win32.ntdll.NtUnmapViewOfSection(
            self.process.handle,
            self.base_remote
        )

        if result:
            raise RuntimeError("Remote unmapping failed, err ", win32.kernel32.GetLastError(), ', ntstatus', result)

        if not win32.kernel32.MapViewOfFile(self.base_local):
            raise RuntimeError("Local unmapping failed, err ", win32.kernel32.GetLastError(), ', ntstatus', result)

        win32.kernel32.CloseHandle(self.map_handle)