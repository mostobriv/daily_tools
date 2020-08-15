# -*- coding: utf-8 -*-

import idaapi

import ida_idaapi
import ida_typeinf

import util
import const
# ida_idaapi.require('util')

# create struct from range
# create struct with predicate


class PtrMember(AbstractMember):
    def __init__(self, pointed_type):
        self.pointed_type = pointed_type

    def retrieve_tinfo(self):
        ptr_tinfo = idaapi.tinfo_t()
        ptr_tinfo.create_ptr(self.pointed_type.retrieve_tinfo())

        return ptr_tinfo


class FuncPtrMember(AbstractMember):
    def __init__(self, concrete_ea=None, custom_name=None):
        super(FuncPtrMember, self).__init__()

        if concrete_ea is not None:
            if util.is_valid_code_addr(concrete_ea):
                self.name = ida_name.get_ea_name(concrete_ea) or 'off'

        self.ea = concrete_ea


    def retrieve_tinfo(self):
        func_tinfo = ida_typeinf.tinfo_t()
        func_tinfo.create_ptr(idaapi.decompile(self.ea).type)
        return func_tinfo


class Array(AbstractMember):
    def __init_(self, elem_type, size, custom_name=None):
        self.elem_type = elem_type
        self.size = size
        self.name = custom_name or 'arr'


    def retrieve_tinfo(self):
        return None

# начни с чего-нибудь хотя бы
# пусть эта залупа просто работает с tinfo_t и udt_t, а дальше уже посмотрим как пойдет

class Member:
    def __init__(self, offset, tinfo, name=None, cmt=None):
        assert tinfo.get_size() != 0

        self.name   = name
        self.offset = offset
        self.type   = tinfo
        self.cmt    = cmt


    @property
    def size(self):
        # size counts in bits like offset
        return self.type.get_size()

class StructProto:

    def __init__(self, name=None, is_union=False):
        self.offset     = 0
        self.name       = name      
        self.is_union   = is_union
        self.fields     = list()

    # def merge(self):
    #   pass

    def add_member(self, tinfo, name=None, cmt=''):
        # member - tinfo_t
        # assert member.size != 0

        if name is None:
            name = 'field_%X' % (self.offset)

        m = Member(name, self.offset, tinfo, cmt)
        self.offset+= m.size
        self.fields.append(m)


    def retrieve_tinfo(self):
        udt = idaapi.udt_type_data_t()
        for m in self.fields:
            new_member = ida_typeinf.udt_member_t()
            new_member.name     = m.name
            new_member.type     = m.type
            new_member.size     = m.size
            new_member.offset   = m.offset
            new_member.cmt      = m.cmt

            udt.push_back(new_member)

        final_tinfo = ida_typeinf.tinfo_t()
        final_tinfo.create_udt(udt, ida_typeinf.BTF_STRUCT)

        return final_tinfo


    @staticmethod
    def check():
        # check that at least no name collisions
        pass


    def import_struct(self):
        cdecl_typedef = '#pragma pack(push, 1)\n' + idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                                            self.retrieve_tinfo(), self.name, None)
        print cdecl_typedef

        previous_ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, self.name)
       
        if previous_ordinal:
            idaapi.del_numbered_type(idaapi.cvar.idati, previous_ordinal)
            ordinal = idaapi.idc_set_local_type(previous_ordinal, cdecl_typedef, idaapi.PT_TYP)
        else:
            ordinal = idaapi.idc_set_local_type(-1, cdecl_typedef, idaapi.PT_TYP)

        if ordinal:
            self.ordinal = ordinal
            print 'Imported struct \'%s\', ordinal %#x' % (self.name, self.ordinal)
            return idaapi.import_type(idaapi.cvar.idati, -1, self.name)
        else:
            print 'Error due importing struct \'%s\', ordinal %#x' % (self.name, ordinal)
            return idaapi.BADNODE
