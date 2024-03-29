from . import win32
from ctypes.wintypes import *
import ctypes as c

class CallBuffer(object):

    def __init__(self, *data):
        self.data = b''.join(data)

class ProcessCaller(object):

    '''
      stdcall:
            push ebp
            mov ebp, esp
            mov esp, dword[esp+8]
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
            mov esp, dword[esp+8]
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
        self._stdcall = proc.mmap(len(ProcessCaller._stdcall_code) + len(ProcessCaller._fastcall_code) + len(ProcessCaller._x64call_code))
        self._fastcall = self._stdcall + len(ProcessCaller._stdcall_code)
        self._x64call = self._fastcall + len(ProcessCaller._fastcall_code)

        proc.write(self._stdcall, ProcessCaller._stdcall_code)
        proc.write(self._fastcall, ProcessCaller._fastcall_code)
        proc.write(self._x64call, ProcessCaller._x64call_code)

        self._stack_size = stack_size
        self._stackbuffer = proc.mapshared(stack_size)
        self.stack = (BYTE * stack_size).from_address(self._stackbuffer.base_local)

    def __del__(self):
        self.process.unmap(self._stdcall)
        self._stackbuffer = None

    def x64call(self, address, *argtypes):
        def _fn(*args):
            cargs = [LPVOID(address)]
            offset = 0
            for i, v in enumerate(argtypes):
                if v is CallBuffer:
                    base = offset
                    d = b''.join(args[i])
                    offset += len(d)
                    self.stack[base:offset] = list(d)
                    cargs.append(LPVOID(self._stackbuffer.base_remote + base))
                else:
                    cargs.append(v(args[i]))
            data = b''.join(cargs)
            base = self._stack_size - max(len(data),0x38)
            offset = base + len(data)
            ptr = self._stackbuffer.base_remote + base
            self.stack[base:offset] = list(data)
            self.process.spawn_thread(self._x64call, ptr).resume()
        return _fn

    def fastcall(self, address, *argtypes):
        def _fn(*args):
            cargs = [LPVOID(address)]
            offset = 0
            for i, v in enumerate(argtypes):
                if v is CallBuffer:
                    base = offset
                    d = b''.join(args[i])
                    offset += len(d)
                    self.stack[base:offset] = list(d)
                    cargs.append(LPVOID(self._stackbuffer.base_remote + base))
                else:
                    cargs.append(v(args[i]))
            data = b''.join(cargs)
            base = self._stack_size - max(len(data),0x38)
            offset = base + len(data)
            ptr = self._stackbuffer.base_remote + base
            self.stack[base:offset] = list(data)
            self.process.spawn_thread(self._fastcall, ptr).resume()
        return _fn

    def stdcall(self, address, *argtypes):
        def _fn(*args):
            cargs = [LPVOID(address)]
            offset = 0
            for i, v in enumerate(argtypes):
                if v is CallBuffer:
                    base = offset
                    d = b''.join(args[i])
                    offset += len(d)
                    self.stack[base:offset] = list(d)
                    cargs.append(LPVOID(self._stackbuffer.base_remote + base))
                else:
                    cargs.append(v(args[i]))
            data = b''.join(cargs)
            base = self._stack_size - max(len(data),0x38)
            offset = base + len(data)
            ptr = self._stackbuffer.base_remote + base
            self.stack[base:offset] = list(data)
            self.process.spawn_thread(self._stdcall, ptr).resume()
        return _fn