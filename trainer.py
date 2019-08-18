class TrainerCheat(object):

    def __init__(self, name, callback, default=False):
        self.name = name
        self.value = False
        self.callback = callback


class Trainer(object):

    def __init__(self):
        self.cheats = []
        
    def option(self, name, default=False):
        def _option(fn):
            cheat = TrainerCheat(name, None, default)
            def __option():
                return fn(cheat)
            cheat.callback = __option
            self.cheats.append(cheat)
            return __option
        return _option


    def poll(self):

        while True:
            os.system('cls')
            for i, v in enumerate(self.cheats):
                if v.value == True:
                    chk = 'X'
                else:
                    chk = ' '
                print('({}) {:<40s} [{}]'.format(i, v.name, chk))
            val = input('> ')
            val = int(val)

            if val < len(self.cheats):
                sel = self.cheats[val]
                sel.value = not sel.value
                sel.callback()