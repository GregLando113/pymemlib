from . import win32

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
        win32.DebugSetProcessKillOnExit(False)
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
        if not win32.DebugActiveProcess(proc.id):
            raise win32.Win32Exception()
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
        frequency = kw.pop("frequency",  win32.INFINITE)
        while self.attached:
            self.poll(frequency)

    def poll(self, timeout= win32.INFINITE):
        """Poll the next event dispatch it"""
        evt = win32.DEBUG_EVENT()
        if not win32.WaitForDebugEvent(byref(evt), timeout):
            return

        if evt.dwProcessId != self.proc.id:
             win32.ContinueDebugEvent(
                evt.dwProcessId, evt.dwThreadId,  win32.DBG_EXCEPTION_NOT_HANDLED
            )
            return

        continue_status =  win32.DBG_CONTINUE
        event_code = evt.dwDebugEventCode
        thread = ProcessThread(evt.dwThreadId, self.proc)

        if event_code == win32.EXCEPTION_DEBUG_EVENT:
            continue_status = self._on_debug_event(thread, evt.u.Exception)
        elif event_code == win32.CREATE_THREAD_DEBUG_EVENT:
            self.OnCreateThreadDebugEvent(thread, evt.u.CreateThread)
        elif event_code == win32.CREATE_PROCESS_DEBUG_EVENT:
            self.OnCreateProcessDebugEvent(thread, evt.u.CreateProcessInfo)
        elif event_code == win32.EXIT_THREAD_DEBUG_EVENT:
            self.OnExitThreadDebugEvent(thread, evt.u.ExitThread)
        elif event_code == win32.EXIT_PROCESS_DEBUG_EVENT:
            self.exit_code = evt.u.ExitProcess.dwExitCode
            self.OnExitProcessDebugEvent(thread, evt.u.ExitProcess)
            self.detach()
        elif event_code == win32.LOAD_DLL_DEBUG_EVENT:
            self.OnLoadDllDebugEvent(thread, evt.u.LoadDll)
        elif event_code == win32.UNLOAD_DLL_DEBUG_EVENT:
            self.OnUnloadDllDebugEvent(thread, evt.u.UnloadDll)
        elif event_code == win32.OUTPUT_DEBUG_STRING_EVENT:
            self.OnOutputDebugStringEvent(thread, evt.u.DebugString)
        elif event_code == win32.RIP_EVENT:
            self.OnRipEvent(evt.u.RipInfo)

        _ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continue_status)

    def _on_single_step(self, thread, addr):
        hook = self.ss_hook
        if not hook:
            return win32.DBG_EXCEPTION_NOT_HANDLED

        hook.enable()
        return _DBG_CONTINUE

    def _on_breakpoint(self, thread, addr):
        proc_hook = self.hooks.get(addr, None)
        if not proc_hook:
            return win32.DBG_EXCEPTION_NOT_HANDLED

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
        return win32.DBG_CONTINUE

    def _on_debug_event(self, thread, info):
        """This is internal, but if you were to overload it, return the continuation status"""
        code = info.ExceptionCode
        if info.dwFirstChance != 1:
            return win32.DBG_EXCEPTION_NOT_HANDLED
        addr = info.ExceptionAddress
        if code == win32.EXCEPTION_SINGLE_STEP:
            return self._on_single_step(thread, addr)
        if code == win32.EXCEPTION_BREAKPOINT:
            return self._on_breakpoint(thread, addr)
        return win32.DBG_EXCEPTION_NOT_HANDLED

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