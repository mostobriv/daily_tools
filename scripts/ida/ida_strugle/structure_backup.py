# -*- coding: utf-8 -*-

import idaapi
import idautils
import idc


from ida_strugle import const
from ida_strugle import util

import re



BAD_C_NAME_PATTERN = re.compile('[^a-zA-Z_0-9:]')


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

class AbstractMember:
    def __init__(self, offset):
        self.offset = offset
        self.is_array = False
        self.suffix = None

    @property
    def type_name(self):
        return self.tinfo.dstr()

    @property
    def size(self):
        size = self.tinfo.get_size()
        return size if size != idaapi.BADSIZE else 1


class Member(AbstractMember):
    def __init__(self, tinfo, offset, name=None):
        AbstractMember.__init__(self, offset)
        self.tinfo = tinfo
        self.name = name if name else "field_{0:X}".format(self.offset)

    # TODO: Member.as_ptr to make pointer from tinfo, but mb it's useless


class Gap(AbstractMember):
    def __init__(self, size, offset, name=None):
        AbstractMember.__init__(self, offset)
        self.name = name if name else "gap_{0:X}".format(self.offset)

        if size == 1:
            self.tinfo = const.BYTE_TINFO
        else:
            array_data = idaapi.array_type_data_t()
            array_data.base = 0
            array_data.elem_type = const.BYTE_TINFO
            array_data.nelems = size
            self.tinfo = idaapi.tinfo_t()
            self.tinfo.create_array(array_data)


class FunctionPointer(AbstractMember):
    def __init__(self, addr, offset):
        AbstractMember.__init__(self, offset)
        self.addr = addr

    @property
    def tinfo(self):
        func_ptr_tinfo = idaapi.tinfo_t()
        decompiled_func =  idaapi.decompile(self.addr) 

        if not decompiled_func or not decompiled_func.type:
            func_ptr_tinfo.create_ptr(const.DUMMY_FUNC)
        else:
            func_ptr_tinfo.create_ptr(decompiled_func.type)

        return func_ptr_tinfo

    @property
    def name(self):
        name = idaapi.get_name(self.addr)
        demangled_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
        if demangled_name:
            name = demangled_name_to_c_str(demangled_name)


        if len(name) == 0:
            name = 'func_%X' % (self.addr)

        if self.suffix:
            return '%s_%s' % (name, self.suffix)
        else:
            return name
    
    @staticmethod
    def check(addr):
        # 1 - check if it's even code
        # 2 - check that addr is pointing to the start of function or imported

        # 1
        if not util.is_code_ea(addr):
            return False

        # 2
        if not util.is_func_start(addr):
            return False

        return True


class Structure(AbstractMember):
    def __init__(self, offset=0, name=None):
        AbstractMember.__init__(self, offset)
        self.offset = offset
        self.name = name
        self.members = list()

    def add_member(self, member):
        if not isinstance(member, AbstractMember):
            raise TypeError('Trying to add member with wrong type: %s' % (member.__class__.__name__))

        self.members.append(member)

    def has_name_collisions(self):
        return len(set([m.name for m in self.members])) != len(self.members)

    def resolve_name_collisions(self):
        for i in range(len(self.members)-1):
            suffix = 0
            for j in range(i+1, len(self.members)):
                if self.members[i].name == self.members[j].name:
                    self.members[j].suffix = str(suffix)
                    suffix+= 1

    def import_struct(self):
        if self.has_name_collisions():
            self.resolve_name_collisions()

        cdecl_typedef = '#pragma pack(push, 1)\n' + idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                                                self.tinfo, self.name, None)

        previous_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, self.name)
       
        if previous_ordinal:
            idaapi.del_numbered_type(idaapi.cvar.idati, previous_ordinal)
            ordinal = idaapi.idc_set_local_type(previous_ordinal, cdecl_typedef, idaapi.PT_TYP)
        else:
            ordinal = idaapi.idc_set_local_type(-1, cdecl_typedef, idaapi.PT_TYP)

        if ordinal:
            self.ordinal = ordinal
            print('Imported struct \'%s\', ordinal %#x' % (self.name, self.ordinal))
            return idaapi.import_type(idaapi.cvar.idati, -1, self.name)
        else:
            print('Error due importing struct \'%s\', ordinal %#x' % (self.name, ordinal))
            print(cdecl_typedef)
            return idaapi.BADNODE

    @property
    def tinfo(self):
        udt = idaapi.udt_type_data_t()
        for m in self.members:
            new_member = idaapi.udt_member_t()
            new_member.name     = m.name
            new_member.type     = m.tinfo
            new_member.size     = m.size
            new_member.offset   = m.offset

            udt.push_back(new_member)

        final_tinfo = idaapi.tinfo_t()
        if final_tinfo.create_udt(udt, idaapi.BTF_STRUCT):
            return final_tinfo


class VirtualTable:
    # TODO: can change type of virtual functions to __thiscall on-fly

    def __init__(self, addr, offset=0, name=None):
        self.addr = addr
        self.name = 'vtab_%X' % offset
        self.vtable_name = 'Vtable_%x' % addr
        self.struct = Structure(offset, self.vtable_name)
        self.populate()

    def populate(self):
        cur_addr = self.addr

        while True:
            if not FunctionPointer.check(util.get_ptr(cur_addr)):
                break

            self.struct.add_member(FunctionPointer(util.get_ptr(cur_addr), cur_addr - self.addr))
            cur_addr+= const.PTR_SIZE

            if len(idaapi.get_name(cur_addr)) != 0:
                break


    def finalize(self):
        return self.struct.import_struct()

    def get_udt_member(self, offset=0):
        udt_member = idaapi.udt_member_t()
        tid = self.import_to_structures()
        if tid != idaapi.BADADDR:
            udt_member.name = self.name
            tmp_tinfo = idaapi.create_typedef(vtable_name)
            tmp_tinfo.create_ptr(tmp_tinfo)
            udt_member.type = tmp_tinfo
            udt_member.offset = self.offset - offset
            udt_member.size = const.EA_SIZE
        return udt_member

    @property
    def n_elems(self):
        return self.struct.size / const.PTR_SIZE

    @property
    def tinfo(self):
        return self.struct.tinfo

    @staticmethod
    def check(addr):
        # 1 - name is defined here == has xref(s)
        # 2 - at least MIN_FUNCTIONS_REQUIRED valid function pointers
        # TODO: 3 - xref's going from instructions like `mov [reg_X], vtable_offset` / `lea reg_X, vtable_offset`
        MIN_FUNCTIONS_REQUIRED = 3

        # 1
        if len(idaapi.get_name(addr)) == 0:
            return False

        # 3
        # ref = idaapi.get_first_dref_to(addr)
        # dref_found = False
        # while ref != idaapi.BADADDR:
        #     insn = idautils.DecodeInstruction(addr)
            
        #     ref = idaapi.get_next_dref_to(addr, ref)
        #     pass


        # if not dref_found:
        #     return False
        

        # 2
        functions_counted = 0
        while True:
            if not FunctionPointer.check(util.get_ptr(addr + functions_counted * const.PTR_SIZE)):
                break

            functions_counted+= 1

            if len(idaapi.get_name(addr + functions_counted * const.PTR_SIZE)) != 0:
                break

        if functions_counted < MIN_FUNCTIONS_REQUIRED:
            return False

        return functions_counted