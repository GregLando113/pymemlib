from memlib import *

proc = Process.from_name('Gw.exe')

send_packet = proc.fastcall(0x00594F60, LPVOID, DWORD, CallBuffer)
gsconn = proc.read(0x00A2441C, 'I')
# send_packet(gsconn, 0x8, [DWORD(0x41), DWORD(0x86)])

if __name__ == '__main__':
    import code
    code.interact(local=locals())
