import idaapi

# import ida_strugle

idaapi.require('ida_strugle')
idaapi.require('ida_strugle.structure')
idaapi.require('ida_strugle.virtual_table')
idaapi.require('ida_strugle.const')
idaapi.require('ida_strugle.util')

from ida_strugle.virtual_table import VirtualTable
from ida_strugle import const, util




def define_all_vtables():
    segments = util.enum_all_segments()
    vtables_total = 0

    for segm in segments:
        addr = segm.start_ea
        while addr < segm.end_ea:
            funcs_counted = VirtualTable.check(addr)
            if funcs_counted:
                try:
                    print(
                        'Found possible vtable: %#x (%s) with %d functions' 
                        % (addr, 
                            repr(idaapi.get_ea_name(addr)),
                            funcs_counted
                          )
                        )

                    v = VirtualTable(addr)
                    v.import_to_idb()
                except Exception as e:
                    print('[!] An error occured due parsing vtable at %#x' % addr)
                    raise e
                
                addr+= funcs_counted * const.PTR_SIZE
                vtables_total+= 1
            addr+= const.PTR_SIZE

    print('[!] Imported %d virtual tables in total!' % vtables_total)


def create_vtable(address):
    try:
        v = VirtualTable(address)
        v.import_to_idb()
        print("Imported: %s" % v.type_name)
    except:
        print("Got an exception!")
