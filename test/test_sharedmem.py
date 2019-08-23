from memlib import *

proc = Process.from_name('test.exe')
mem = proc.mapshared(0x100)
buf = (BYTE * 0x100).from_address(mem.base_local)

print(f'mem.base_local={hex(mem.base_local)}')
print(f'mem.base_remote={hex(mem.base_remote)}')

if __name__ == '__main__':
    import code
    code.interact(local=locals())