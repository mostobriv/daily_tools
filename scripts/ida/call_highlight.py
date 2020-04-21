import idaapi, idautils, idc

DEFCOLOR = 0xffffffff
COLOR_CALL = 0xffffd0


def findUnidentifiedFunctions():
    # just get all not-function code and convert it to functions
    next = idaapi.cvar.inf.minEA
    while next != idaapi.BADADDR:
        next = idaapi.find_not_func(next, idaapi.SEARCH_DOWN)
        flags = idaapi.getFlags(next)
        if idaapi.isCode(flags):
            idc.MakeFunction(next)


def colorize(addr, color):
    idaapi.set_item_color(addr, color)


def revokeAnalysis():
    n = idaapi.netnode("$ initialAnalysis", 0, False)

    if (n == idaapi.BADNODE):   return

    idx = n.alt1st()
    while idx != idaapi.BADNODE:
        colorize(idx, DEFCOLOR)
        idx = n.altnxt(idx)

    n.kill()

    idaapi.refresh_idaview_anyway()


def setEaInfo(ea, info=""):
    n = idaapi.netnode("$ initialAnalysis", 0, True)
    n.set(info)


def setFunctionInfo(ea, color, info=""):
    f = idaapi.get_func(ea)
    if not f:   return
    setEaInfo(f.startEA, info)


def setInfo(ea, color, info=""):
    colorize(ea, color)
    setEaInfo(ea, info)
    setFunctionInfo(ea, info)

class CallTester(object):
    def __init__(self):
        pass

    def instruction(self, cmd):
        if idaapi.is_call_insn(cmd.ea):
            setInfo(cmd.ea, COLOR_CALL)


def iterateInstructions():
    next = 0
    while next != idaapi.BADADDR:

        # get next instruction
        next = idc.NextHead(next)

        idaapi.decode_insn(next)
        for handlers in InstructionCallbacks:
            handlers.instruction(idaapi.cmd)


### main ###
revokeAnalysis()

# find unidentified functions
findUnidentifiedFunctions()

InstructionCallbacks = []
InstructionCallbacks.append(CallTester())

iterateInstructions()

# refresh ida view to display our results
idaapi.refresh_idaview_anyway()

print "done. have a nice day :-)"
