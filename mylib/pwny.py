from os import system
from pwn import Coredump
from functools import wraps

# it doesn't work actually, need to make it work (also mb changed ways this func communicates with sender/receiver)
def padding_finder(path):
    def padding_finder_inner(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            system('ulimit -c unlimited')

            func(*args, **kwargs)

            core = Coredump('{}/core'.format(path))
            system('ulimit -c 0')
            system('rm -rf {}/core'.format(path))
            
            return cyclic_find(core.pc)
        return wrapper
    return padding_finder_inner
