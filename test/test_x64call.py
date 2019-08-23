from memlib import *

proc = Process.from_name('test.exe')
call = ProcessCaller(proc)
add = call.x64call(0x00007FF6CC1F1000, LARGE_INTEGER, LARGE_INTEGER)
add(10,10)

if __name__ == '__main__':
    import code
    code.interact(local=locals())