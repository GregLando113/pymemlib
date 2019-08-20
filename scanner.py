
class ProcessScanner(object):
    """
    Class used to scan remote process's code section.
    """

    def __init__(self, proc):
        self.proc = proc
        self.module = proc.module()
        if not self.module:
            raise RuntimeError("Couldn't find default module")
        # Very hacky but that will do it for now
        self.base = self.module.base + 0x1000
        size, _ = proc.page_info(self.base)
        self.buffer, = proc.read(self.base, "%ds" % size)

    def find(self, pattern, offset=0):
        """Returns address of the pattern if found."""
        match = self.buffer.find(pattern)
        if not match:
            raise RuntimeError("Couldn't find the pattern.")
        return self.base + match + offset

    def __repr__(self):
        return "<Scanner 0x%08x for Process %d>" % (id(self), self.proc.id)