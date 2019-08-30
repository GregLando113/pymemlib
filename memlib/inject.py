from . import win32

def InjectDll(proc, name):
    """Inject a dll with CreateRemoteThread in the remote process"""

    class InjectionError(RuntimeError):
        pass
        
    kernel32 = win32.GetModuleHandleA(b"kernel32")
    if not kernel32:
        raise win32.Win32Exception()
    LoadLibraryEx = win32.GetProcAddress(kernel32, b"LoadLibraryA")
    if not LoadLibraryEx:
        raise win32.Win32Exception()
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
    kernel32 = win32.GetModuleHandleA(b"kernel32")
    if not kernel32:
        raise win32.Win32Exception()
    FreeLibraryEx = win32.GetProcAddress(kernel32, b"FreeLibraryA")
    if not FreeLibraryEx:
        raise win32.Win32Exception()
    thread = proc.spawn_thread(FreeLibraryEx, handle)
    thread.resume()
    retval = thread.join()

