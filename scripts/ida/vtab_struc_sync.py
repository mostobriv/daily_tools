from __future__ import print_function
import idaapi
import idautils
import ida_name
import ida_funcs
import ida_struct
import ida_typeinf
import idc_bc695

import idc

import re


BAD_C_NAME_PATTERN = re.compile('[^a-zA-Z_0-9:]')

# for compatibility with HexRaysPyTools
def demangled_name_to_c_str(name):
    """
    Removes or replaces characters from demangled symbol so that it was possible to create legal C structure from it
    """

    if not BAD_C_NAME_PATTERN.findall(name):
        return name

    # FIXME: This is very ugly way to find and replace illegal characters
    idx = name.find("::operator")
    if idx >= 0:
        idx += len("::operator")
        if idx == len(name) or name[idx].isalpha():
            # `operator` is part of name of some name and not a keyword
            pass
        elif name[idx:idx + 2] == "==":
            name = name.replace("operator==", "operator_EQ_")
        elif name[idx:idx + 2] == "!=":
            name = name.replace("operator!=", "operator_NEQ_")
        elif name[idx] == "=":
            name = name.replace("operator=", "operator_ASSIGN_")
        elif name[idx:idx + 2] == "+=":
            name = name.replace("operator+=", "operator_PLUS_ASSIGN_")
        elif name[idx:idx + 2] == "-=":
            name = name.replace("operator-=", "operator_MINUS_ASSIGN_")
        elif name[idx:idx + 2] == "*=":
            name = name.replace("operator*=", "operator_MUL_ASSIGN_")
        elif name[idx:idx + 2] == "/=":
            name = name.replace("operator/=", "operator_DIV_ASSIGN_")
        elif name[idx:idx + 2] == "%=":
            name = name.replace("operator%=", "operator_MODULO_DIV_ASSIGN_")
        elif name[idx:idx + 2] == "|=":
            name = name.replace("operator|=", "operator_OR_ASSIGN_")
        elif name[idx:idx + 2] == "&=":
            name = name.replace("operator&=", "operator_AND_ASSIGN_")
        elif name[idx:idx + 2] == "^=":
            name = name.replace("operator^=", "operator_XOR_ASSIGN_")
        elif name[idx:idx + 3] == "<<=":
            name = name.replace("operator<<=", "operator_LEFT_SHIFT_ASSIGN_")
        elif name[idx:idx + 3] == ">>=":
            name = name.replace("operator>>=", "operator_RIGHT_SHIFT_ASSIGN_")
        elif name[idx:idx + 2] == "++":
            name = name.replace("operator++", "operator_INC_")
        elif name[idx:idx + 2] == "--":
            name = name.replace("operator--", "operator_PTR_")
        elif name[idx:idx + 2] == "->":
            name = name.replace("operator->", "operator_REF_")
        elif name[idx:idx + 2] == "[]":
            name = name.replace("operator[]", "operator_IDX_")
        elif name[idx] == "*":
            name = name.replace("operator*", "operator_STAR_")
        elif name[idx:idx + 2] == "&&":
            name = name.replace("operator&&", "operator_LAND_")
        elif name[idx:idx + 2] == "||":
            name = name.replace("operator||", "operator_LOR_")
        elif name[idx] == "!":
            name = name.replace("operator!", "operator_LNOT_")
        elif name[idx] == "&":
            name = name.replace("operator&", "operator_AND_")
        elif name[idx] == "|":
            name = name.replace("operator|", "operator_OR_")
        elif name[idx] == "^":
            name = name.replace("operator^", "operator_XOR_")
        elif name[idx:idx + 2] == "<<":
            name = name.replace("operator<<", "operator_LEFT_SHIFT_")
        elif name[idx:idx + 2] == ">>":
            name = name.replace("operator>", "operator_GREATER_")
        elif name[idx:idx + 2] == "<=":
            name = name.replace("operator<=", "operator_LESS_EQUAL_")
        elif name[idx:idx + 2] == ">=":
            name = name.replace("operator>>", "operator_RIGHT_SHIFT_")
        elif name[idx] == "<":
            name = name.replace("operator<", "operator_LESS_")
        elif name[idx] == ">":
            name = name.replace("operator>=", "operator_GREATER_EQUAL_")
        elif name[idx] == "+":
            name = name.replace("operator+", "operator_ADD_")
        elif name[idx] == "-":
            name = name.replace("operator-", "operator_SUB_")
        elif name[idx] == "/":
            name = name.replace("operator/", "operator_DIV_")
        elif name[idx] == "%":
            name = name.replace("operator%", "operator_MODULO_DIV_")
        elif name[idx:idx + 2] == "()":
            name = name.replace("operator()", "operator_CALL_")
        elif name[idx: idx + 6] == " new[]":
            name = name.replace("operator new[]", "operator_NEW_ARRAY_")
        elif name[idx: idx + 9] == " delete[]":
            name = name.replace("operator delete[]", "operator_DELETE_ARRAY_")
        elif name[idx: idx + 4] == " new":
            name = name.replace("operator new", "operator_NEW_")
        elif name[idx: idx + 7] == " delete":
            name = name.replace("operator delete", "operator_DELETE_")
        elif name[idx:idx + 2] == "\"\" ":
            name = name.replace("operator\"\" ", "operator_LITERAL_")
        elif name[idx] == "~":
            name = name.replace("operator~", "operator_NOT_")
        elif name[idx] == ' ':
            pass
        else:
            raise AssertionError("Replacement of demangled string by c-string for keyword `operatorXXX` is not yet"
                                 "implemented ({}). You can do it by yourself or create an issue".format(name))

    name = name.replace("public:", "")
    name = name.replace("protected:", "")
    name = name.replace("private:", "")
    name = name.replace("~", "DESTRUCTOR_")
    name = name.replace("*", "_PTR")
    name = name.replace("<", "_t_")
    name = name.replace(">", "_t_")
    name = "_".join(filter(len, BAD_C_NAME_PATTERN.split(name)))
    return name


class RnSyncState:
    RNST_NTHNG  = 0
    RNST_FUNC   = 1
    RNST_STMEMB = 2

    STATE = RNST_NTHNG

    LAST_EA = 0
    FUNC_OLDNAME = str()

    LAST_SID, LAST_MID = 0, 0
    OLD_MEMB_NAME = str()


    @staticmethod
    def clear():
        STATE           = 0

        LAST_EA         = 0
        FUNC_OLDNAME    = str()

        LAST_SID        = 0
        LAST_MID        = 0
        OLD_MEMB_NAME   = str()


#--------------------------------------------------------------------------
class my_idp_hook_t(idaapi.IDP_Hooks):
    def ev_rename(self, ea, newname):

        func = ida_funcs.get_func(ea)
        if func is None or func.start_ea != ea:
            return 0

        oldname = demangled_name_to_c_str(idc.get_name(ea, gtn_flags=(ida_name.GN_VISIBLE | ida_name.GN_DEMANGLED)))
        print('ev_rename: %#x: %s -> %s' % (ea, oldname, newname))

        RnSyncState.STATE           = RnSyncState.RNST_FUNC
        RnSyncState.LAST_EA         = ea
        RnSyncState.FUNC_OLDNAME    = oldname

        return 0

#--------------------------------------------------------------------------
class my_idb_hook_t(idaapi.IDB_Hooks):

    # kernel renamed some byte
    def renamed(self, ea, new_name, local_name):

        print('renamed: %#x: %s, is_local_name = %d' % (ea, new_name, local_name))

        try:
            if not local_name:
                if RnSyncState.STATE != 0:
                    if RnSyncState.STATE == RnSyncState.RNST_FUNC and RnSyncState.LAST_EA == ea:
                        print('function renamed %s' % RnSyncState.FUNC_OLDNAME)
                        idati = ida_typeinf.get_idati()
                        types_amount = ida_typeinf.get_ordinal_qty(idati)
                        RnSyncState.STATE = RnSyncState.RNST_NTHNG
                        for ordinal in xrange(1, types_amount):
                            ti = ida_typeinf.tinfo_t()
                            if ti.get_numbered_type(idati, ordinal):
                                struc_name = ti.get_type_name().lower()
                                # better rewrite this to ida_struct and new api
                                # do it Simon!
                                if struc_name.startswith('vtable') or struc_name.startswith('vftable'):
                                    sid = idc_bc695.GetStrucIdByName(ti.get_type_name())
                                    sofs = idc_bc695.GetFirstMember(sid)
                                    eofs = idc_bc695.GetLastMember(sid)
                                    while sofs <= eofs:
                                        mname = idc_bc695.GetMemberName(sid, sofs)
                                        if not (mname is None) and mname == RnSyncState.FUNC_OLDNAME:
                                            # found
                                            idc_bc695.SetMemberName(sid, sofs, new_name)

                                        sofs+= idc_bc695.GetMemberSize(sid, sofs)


                        RnSyncState.clear()

                    elif RnSyncState.STATE == RnSyncState.RNST_STMEMB:
                        pass

                    else:
                        print("%#x %#x" % (RnSyncState.LAST_EA, ea))
                        print('idk what the fuck is this state: %#x' % RnSyncState.STATE)

                    RnSyncState.STATE = RnSyncState.RNST_NTHNG
        except Exception as e:
            print(e)
            RnSyncState.clear()

        return 0

    # kernel renamed struct member
    def struc_member_renamed(self, sptr, mptr):
        # idk why the fuck ida is calling this function on non-struct types
        if sptr.ordinal < 0:
            return 0

        print('Rename %s to %s' % (RnSyncState.OLD_MEMB_NAME, ida_struct.get_member_name(mptr.id)))

        struc_name = ida_struct.get_struc_name(sptr.id).lower()
        member_name = ida_struct.get_member_name(mptr.id)

        # simple heuristic
        if struc_name.startswith('vtable') or struc_name.startswith('vftable'):
            addr = idc_bc695.LocByName(RnSyncState.OLD_MEMB_NAME)
            if addr != idaapi.BADADDR:
                RnSyncState.STATE = RnSyncState.RNST_NTHNG
                idc_bc695.MakeNameEx(addr, member_name, idc_bc695.SN_NOWARN)
            else:
                pass
        else:
            pass

        RnSyncState.clear()

        return 0

    # kernel is about to rename struct member
    def renaming_struc_member(self, sptr, mptr, newname):

        print('s.id = %#x, s.ordinal = %d' % (sptr.id, sptr.ordinal))
        print('m.id = %#x' % (mptr.id))
        # idk why the fuck ida is calling this function on non-struct types
        if sptr.ordinal < 0:
            return

        try:
            RnSyncState.STATE           = RnSyncState.RNST_STMEMB
            RnSyncState.LAST_MID        = mptr.id
            RnSyncState.LAST_SID        = sptr.id
            RnSyncState.OLD_MEMB_NAME   = ida_struct.get_member_name(mptr.id)

            print('About to rename: %s' % ida_struct.get_member_name(mptr.id))
            print('renaming_struc_member: %s - %s, newname = %s' % (sptr, mptr, newname))

        except Exception as e:
            print('[EXCEPTION] %s' % str(e))


        return 0




#---------------------------------------------------------------------
# Remove an existing hook on second run
try:
    hook_stat = "un"
    print("hooks: checking for hook.B.")
    idbhook
    idphook
    print("hooks: unhooking....")
    idbhook.unhook()
    idphook.unhook()
    del idbhook
    del idphook
except Exception as e:
    print(e)
    print("hooks: not installed, installing now....")
    hook_stat = ""
    idbhook = my_idb_hook_t()
    idphook = my_idp_hook_t()
    idbhook.hook()
    idphook.hook()

print("hooks %sinstalled. Run the script again to %sinstall" % (hook_stat, hook_stat))
