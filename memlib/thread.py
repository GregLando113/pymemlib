from . import win32

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

        self.handle = handle or win32.OpenThread(win32.THREAD_ALL_ACCESS, False, id)
        if not self.handle:
            raise win32.Win32Exception()

    def __del__(self):
        win32.CloseHandle(self.handle)

    def __eq__(self, other):
        return self.id == other.id

    def __repr__(self):
        return "<ProcessThread %d in Process %d>" % (self.id, self.pid)

    def kill(self, code=0):
        """Terminates the Thread with the given exit code."""
        success = win32.TerminateThread(self.handle, code)
        if not success:
            raise win32.Win32Exception()

    @property
    def alive(self):
        """Checks if the thread is still executing."""
        code = DWORD()
        success = win32.GetExitCodeThread(self.handle, byref(code))
        if not success:
            raise win32.Win32Exception()
        return code.value == 259  # STILL_ACTIVE = 259

    def resume(self):
        """Resumes the thread."""
        count = win32.ResumeThread(self.handle)
        if count == 0xFFFFFFFF:
            raise win32.Win32Exception()

    def suspend(self):
        """Suspends the thread."""
        count = win32.SuspendThread(self.handle)
        if count == 0xFFFFFFFF:
            raise win32.Win32Exception()

    def join(self, timeout=win32.INFINITE):
        """Waits until the thread exit and returns the exit code."""
        reason = win32.WaitForSingleObject(self.handle, timeout)
        if reason != _WAIT_OBJECT_0:
            raise RuntimeError("Thread has been terminated prematurely.")
        code = DWORD()
        success = win32.GetExitCodeThread(self.handle, byref(code))
        if not success:
            raise win32.Win32Exception()
        return code.value

    def context(self, flags=win32.CONTEXT_FULL):
        """Retrieves the context of the ProcessThread."""
        context = win32.CONTEXT()
        context.ContextFlags = flags
        success = win32.GetThreadContext(self.handle, byref(context))
        if not success:
            raise win32.Win32Exception()
        return context

    def set_context(self, context):
        """Sets the context for the ProcessThread."""
        success = win32.SetThreadContext(self.handle, byref(context))
        if not success:
            raise win32.Win32Exception()

    @property
    def teb(self):
        """Returns the address of the thread's information/environment block"""
        info = win32.THREAD_BASIC_INFORMATION()
        ntstatus = win32.NtQueryInformationThread(
            self.handle, win32.ThreadBasicInformation, byref(info), sizeof(info), None
        )
        # Need confirmation, but WinDll default returns type is int and
        # NTSUCCESS are positive signed 32 bytes integers [0 - 0x7fffffff]
        if ntstatus < 0:
            raise win32.Win32Exception()
        return info.TebBaseAddress