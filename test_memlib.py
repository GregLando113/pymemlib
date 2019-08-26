from memlib import *

proc = Process.from_name('Gw.exe')

send_packet = proc.fastcall(0x00594F60, LPVOID, DWORD, CallBuffer)
gsconn = proc.read(0x00A2441C, 'I')
# send_packet(gsconn, 0x8, [DWORD(0x41), DWORD(0x86)])

#0x00895EB4


class TestGWClass(RemoteClass):

    fl1 = RemoteClass.Field(0x0000, 'f')
    fl2 = RemoteClass.Field(0x0004, 'f')
    fl3 = RemoteClass.Field(0x0008, 'f')
    fl4 = RemoteClass.Field(0x000c, 'f')
    fl5 = RemoteClass.Field(0x0010, 'f')
    fl6 = RemoteClass.Field(0x0014, 'f')
    fl7 = RemoteClass.Field(0x0018, 'f')
    screen = RemoteClass.Field(0x001C, '32s')


if __name__ == '__main__':
    import code
    code.interact(local=locals())
