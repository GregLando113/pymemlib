from memlib import *
from .memory import (
    send_packet_addr,
    gs_conn_addr
)


class MsgConn(object):

    def __init__(self, proc):
        self.proc = proc
        self._sendpacket_caller = proc.fastcall(send_packet_addr, LPVOID, DWORD, CallBuffer)

    def send(self, size, *args):
        return self._sendpacket_caller(self.proc.read(gs_conn_addr, 'P'), size, args)




if __name__ == '__main__':
    proc = Process.from_name("Gw.exe")
    conn = MsgConn(proc)

    import code
    code.interact(local=locals())