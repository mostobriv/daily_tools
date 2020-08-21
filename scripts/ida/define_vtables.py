import idaapi

# import ida_strugle

idaapi.require('ida_strugle')
idaapi.require('ida_strugle.structure')
idaapi.require('ida_strugle.const')
idaapi.require('ida_strugle.util')

from ida_strugle.structure import VirtualTable
from ida_strugle import const, util




def define_vtables():
    segments = util.enum_all_segments()
    vtables_total = 0

    for segm in segments:
        addr = segm.start_ea
        while addr < segm.end_ea:
            funcs_counted = VirtualTable.check(addr)
            if funcs_counted:
                print 'Found possible vtable: %#x (%s) with %d functions' % (addr, repr(idaapi.demangle_name(idaapi.get_ea_name(addr), idc.get_inf_attr(idc.INF_SHORT_DN))), funcs_counted)
                v = VirtualTable(addr)
                
                v.finalize()
                addr+= funcs_counted * const.PTR_SIZE
                vtables_total+= 1
            addr+= const.PTR_SIZE

    print '[!] Imported %d virtual tables in total!' % vtables_total
