

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


if __name__ == '__main__':
    pass