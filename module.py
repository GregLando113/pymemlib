class ProcessModule(object):
    """
    A Win32 process module object.
    
    Properties:
        - handle
        - pid
        - name
        - base
        - size
        - file
    """

    def __init__(self, handle, process):
        self.handle = handle
        self.pid = process.id

        # make sure all properties are initialized
        self.name = None
        self.base = None
        self.size = None
        self.file = None

    def __eq__(self, other):
        return (self.handle == other.handle) and (self.pid == other.pid)

    def __str__(self):
        return "0x%08x %s" % (self.base, self.name)

    def __repr__(self):
        return "<ProcessModule %s in Process %d>" % (str(self), self.pid)

    @classmethod
    def from_MODULEENTRY32(cls, module, process):
        mod = ProcessModule(module.hModule, process)
        mod.name = module.szModule.decode("ascii").lower()
        mod.base = module.modBaseAddr
        mod.size = module.modBaseSize
        mod.file = module.szExePath.decode("ascii")
        return mod