from memlib import *

proc = Process.from_name("Gw.exe")
scan = ProcessScanner(proc)

agent_array_addr  = scan.find(b"\x56\x8B\xF1\x3B\xF0\x72\x04", 0xC)
agent_array_addr  = proc.read(agent_array_addr, 'P')
player_id_addr    = proc.read(agent_array_addr + 0x54, 'P')
target_id_addr    = proc.read(agent_array_addr + 0x500, 'P')
mouseover_id_addr = proc.read(agent_array_addr + 0x4F4, 'P')

send_packet_addr  = scan.find(b"\x55\x8B\xEC\x83\xEC\x2C\x53\x56\x57\x8B\xF9\x85")

gs_conn_addr      = scan.find(b"\x56\x33\xF6\x3B\xCE\x74\x0E\x56\x33\xD2", -4)
gs_conn_addr      = proc.read(gs_conn_addr, 'P')

map_id_addr       = scan.find(b"\xB0\x7F\x8D\x55", 0x46)
map_id_addr       = proc.read(map_id_addr, 'P')

thread_ctx_addr   = scan.find(b"\x8B\x42\x0C\x56\x8B\x35", 6)
thread_ctx_addr   = proc.read(thread_ctx_addr, 'P')


scan = None
proc = None