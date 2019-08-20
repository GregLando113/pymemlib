stdcall: ; also does cdecl since we use a fake stack
        push ebp
        mov ebp, esp
        mov esp, dword[esp+8]
        pop eax
        call eax
        xor eax, eax
        mov esp, ebp
        pop ebp
        ret 4

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