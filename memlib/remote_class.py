

class RemoteClass(object):

    class Field(object):

        def __init__(self, offset, fmt, **kw):
            self.offset = offset
            self.fmt = fmt
            self.inst = None
            self.cast = kw.pop('cast', None)


        def __get__(self, inst, *_):
            val = inst.read(self.offset, self.fmt)

            if self.cast:
                return self.cast(inst, val)
            return val


    def __init__(self, proc, base):
        self.proc = proc
        self.base = base

    def read(self, offset, fmt):
         return self.proc.read(self.base + offset, fmt)


class TestClass(RemoteClass):

    test1 = RemoteClass.Field(0x40, 'I')
    test2 = RemoteClass.Field(0x44, 'I')
    test3 = RemoteClass.Field(0x48, 'ff')


if __name__ == '__main__':
    import code
    code.interact(local=locals())