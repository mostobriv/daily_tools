import idaapi, idautils, idc

COLOR_CALL = 0xffffd0


def iterateInstructions():

    next_instr = 0
    while next_instr != idaapi.BADADDR:

        # get next instruction
        next_instr = idc.NextHead(next_instr)

        idaapi.decode_insn(next_instr)
        if idaapi.is_call_insn(idaapi.cmd.ea):
            setInfo(idaapi.cmd.ea, COLOR_CALL)


iterateInstructions()

# refresh ida view to display our results
idaapi.refresh_idaview_anyway()
