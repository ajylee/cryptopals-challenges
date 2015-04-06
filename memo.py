

memory = {}


def memo(name, thunk):
    if name in memory:
        return memory[name]
    else:
        val = thunk()
        memory[name] = val
        return val
